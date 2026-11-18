# Roadmap

## Milestones

| # | Scope | Exit criterion | Status |
|---|---|---|---|
| M1 | Tables (program, cpu, memory, alu, byte), ISA row M1, syscalls 0–1, ZK on, tier padding, assembler, emulator, tests, guidance README + `docs/01–05` | `fib`, `memcpy`, `bubble_sort`, `alu_mix` (and `balance_check`) prove and verify with ZK at their tiers; all cheating tests reject | **done** — 44 tests pass, the narrated demo runs clean |
| M1.5 | Viewing keys: a one-in-one-out shielded transfer guest with in-circuit commitments and nullifier (software `Arx8` hash), note envelopes (ML-KEM-768 + ChaCha20-Poly1305), party- and transaction-scoped disclosure, row verification against the chain, a simulated ledger (`docs/06-viewing-keys.md`) | a transfer proves at tier 12 and a ledger accepts it; each disclosure scope opens exactly its own rows; every row verifies; a viewing key cannot spend | **done** — 6 tests, Part 9 of the demo |
| M2 | Sub-word loads/stores, the M extension, a flat-binary loader, `READ_INPUT` bound to something | a guest compiled with an external RISC-V toolchain runs and proves | **done** (M2.1–M2.6, this milestone's six-task implementation plan): verifier key cache — done; FRI retuned to a 100-bit conjectured target — done, and **reverted 2026-09-12 on the zk audit** (deviation 6 below: the retune kept the conjectured bound but gave up the proven proximity-gaps floor; `Production` is back to the whitepaper's 80/8/20); the 2^16-row byte table split into 256-row range and nibble tables — done; the ALU's RANGE8 limb checks collapsed to op-gated (`g_ab`/`g_c`) — done; sub-word loads/stores `LB LH LBU LHU SB SH` as a read-modify-write over word-addressed memory — done; the RV32M extension (`MUL MULH MULHU MULHSU DIV DIVU REM REMU`) as exact integer identities — done; 81 tests total. The flat-binary loader and a firmer `READ_INPUT` binding, carried forward as open items, were closed in M4.1 (`docs/superpowers/plans/2026-09-11-zkvm-m4-1.md`) |
| M3 | Poseidon2 chip, `POSEIDON2` syscall plus `NOTE_COMMIT`/`NULLIFY`/`MERKLE_VERIFY` guest routines, program digest moved in-circuit as a public value; `Arx8` retired and `cm_in` moved from public output to Merkle witness | the zkp6/zkp4 transfer relation re-expressed as a guest proves under `R_exec`, with membership in-circuit | **done** — M3.1 (Poseidon2 chip, one row per round, `POSEIDON2` bus), M3.2 (`POSEIDON2` syscall = 3, absorb/write-back cpu hash rows), M3.3 (`NOTE_COMMIT`/`NULLIFY`/`MERKLE_VERIFY` guest routines, the transfer guest rewritten around in-circuit membership, the ledger's commitment tree, `Arx8` retired) and M3.4 (the program table as a witness trace with an in-circuit decoder, `hc` as an in-circuit digest pinned to `pv::HC0..HC7`, `Machine::verify(hc, proof)`, the verifier key collapsed to one per (tier, declared program height) — deviation 1 below closed) all done — 117 tests, `docs/06-viewing-keys.md` |
| M4 | EVM and sBPF guest interpreters, Keccak/SHA coprocessors (`docs/04-guests.md`) | an ERC-20 `transfer` and an SPL `Transfer` each prove under `R_exec` | in progress — **met on neither side as an actually-produced proof on the development hardware; since constraint set 6, for the same reason on both sides: memory** (below). M4.1 (compiled guests, flat-binary loader, `READ_INPUT` bound to `H_IN`) **done**. M4.2 (the Keccak-f\[1600\] chip, `KECCAK` syscall = 4, proof-declared keccak and memory heights, the keccak table optional per proof, the compiled `keccak256` guest) **done** — the suite stood at 223 tests then (222 pass, 1 ignored), M4.2 adding 38 of them (`tests/keccak.rs` (12, new), `tests/cheating.rs` (+15), `tests/e2e.rs` (+6), `tests/tables.rs` (+5)) and the 2026-09-12 audit port a further 18 (`tests/cheating.rs` (+11), `tests/asm.rs` (+5), `tests/e2e.rs` (+1), `tests/emulator.rs` (+1)). M4.3 (the EVM interpreter guest: `evm-core` as a `no_std` library over a two-method `Host`, the depth-32 Poseidon2 storage tree, the `EVM_OUT` public-output digest, the loader's image container so a compiled guest may have a data segment, and the compiled `evm` guest running Solidity's own ERC-20 runtime bytecode) **done** — an ERC-20 `transfer` executes in the guest, binds its state-root transition and measures at **`Tier(18)`** (deviation 7 below), and the same guest binary proves and verifies in-suite on a smaller storage read-modify-write at `Tier(16)` — the transfer's own tier-18 proof was **not produced on the development machine (48 GB): three attempts, ≥ 28.5 GB resident at SIGKILL**, so it is an `#[ignore]`d test — `cd research && cargo +1.98.1 test --release --test e2e compiled_evm_erc20_transfer_proves_at_tier_18 -- --ignored --nocapture` on a **≥ 64 GB** machine produces it, and the alternative is the storage `MERKLE_VERIFY`-syscall follow-up bringing the call under tier 16, where the proof is 774 KB and seven minutes (`docs/04-guests.md`); it added 54 tests (`tests/evm_u256.rs` (6, new), `tests/evm_storage.rs` (13, new), `tests/evm_interp.rs` (17, new), `tests/evm_abi.rs` (8, new), `tests/isa.rs` (+5, the image container), `tests/e2e.rs` (+5: three running plus two `#[ignore]`d — the tier-18 transfer proof and a production-profile measurement)), taking the suite from 223 to 277 (274 pass, 3 ignored) on its own branch. M4.4 took its image-container loader (`Program::from_flat_image`, the `li`/`sw` data prologue, `guests-compiled/mkimage.py`, +5 in `tests/isa.rs`) by cherry-pick, because a compiled interpreter always has a `.rodata`. M4.4 **built, and unprovable at any tier this machine had until constraint set 6**: the SHA-256 chip and `SHA256` syscall = 5 are done (`tables::sha256`, 466 + 10 columns, degree 3, optional per proof, the verifier key a 5-tuple then, a 6-tuple now; `guests::sha256_demo` proves at tier 10), `sbpf-core` is done (the SBPF v1 ISA, memory regions, interpreter, syscalls, ELF loader and ABI, differentially tested against `solana-sbpf` 0.11.1), and so are the compiled `sbpf` guest and the committed SPL Token program — which **runs** a real SPL `Transfer`, publishing the eight documented output words byte for byte as the native interpreter does. As M4.4 shipped it that run took **1 753 945 cycles** against `Tier(20)`'s 1 048 575: the 108 600-byte ELF was 1 698 of the run's 2 368 compressions (72 %), and carrying and hashing it in-circuit as `program_hash` = `sha256(elf bytes)` was about 1.20 M of the 1.75 M cycles (69 %) — hashing that **could not simply be dropped**, because `H_IN` is salted and hiding, so a declared digest the guest does not recompute would be bound to nothing. **Constraint set 6 took remedy (B)** and the numbers moved accordingly: **694 498 cycles, 30 compressions, `sha256_log_height` 11, `Tier(20)`** (remedy (A), baking the ELF into the guest's data segment, was declined — it lands at the same tier, makes the guest program-specific, and is ~20 % over the loaders' 65 535-word program cap until the prologue's `lui` half is deduped). What remains outstanding is the artefact rather than the design: a tier-20 batch is four times the cpu rows of M4.3's tier-18 one, which was SIGKILLed here at ≥ 28.5 GB resident, so it needs the same **≥ 64 GB** machine — `cd research && cargo +1.98.1 test --release --test e2e compiled_sbpf_spl_token_transfer_proves_and_verifies -- --ignored --nocapture`. Reaching the milestone's *stated* tier 18 needs the tape cost addressed (a bulk public-read syscall — spec §9.5's open item), not another binding change. Design spec §5.1 item 8 and §9 are the decision record; `docs/04-guests.md`'s "The `sbpf` guest" has the measured breakdown and both remedies' costs. The merged M4 suite was **365 tests (359 pass, 6 ignored)** — 395 (389 pass, 6 ignored) since constraint set 6, the CS6 row below: M4.2's 223 plus M4.3's 54 and M4.4's 93, less the five `tests/isa.rs` image-container tests both lists count (M4.4 took them from M4.3 by cherry-pick, so they are the same five tests). M4.4's chip tasks added 32 (`tests/sha256.rs` (14, new), `tests/cheating.rs` (+11), `tests/e2e.rs` (+4), `tests/emulator.rs` (+2), `tests/tables.rs` (+1)), Task 5's interpreter 49 (`tests/sbpf_interp.rs` (20, new), `tests/sbpf_abi.rs` (13, new), `tests/sbpf_elf.rs` (10, new), `tests/sbpf_isa.rs` (6, new)) and Task 6 a further 12 (`tests/isa.rs` (+5, cherry-picked), `tests/e2e.rs` (+4, two of them `#[ignore]`d — the exit test and the cycle-breakdown measurement), `tests/sbpf_abi.rs` (+2, the SPL Token fixture natively and against the oracle), `tests/sbpf_elf.rs` (+1, the pseudo-call normalisation), and the SPL Token ELF case Task 5 left `#[ignore]`d is now passing). |
| CS6 | **The public input segment** (design spec §9, 2026-09-13): a second, *unsalted* input space — the `public` witness table, the `PUBLIC_DIGEST`/`PUBLIC_READ` bus pair, the `IS_PUBDIGEST` cpu region computing `H_PUB` into `pv::PUB0..PUB7`, `SYS_READ_PUBLIC = 6` with its SDK and asm wrappers, `Machine::verify_public`, and the sBPF guest rebound onto it | a guest reads the segment and proves; a verifier holding the words recomputes `H_PUB` and accepts, and rejects a wrong word list or a wrong length; every §13-style forgery against the new table and region is rejected; the sBPF exit test re-measured | **done** — the suite is **395 tests (389 pass, 6 ignored)**, measured at 1 032 s wall and 23.1 GiB peak resident in one 2026-09-13 run of the 394-test tree (the final review's one added cheating test costs ~2 s more). Of the 30 new tests the largest share — 17 — is in `tests/cheating.rs`, which grew 94 → **111** on the `public` table and its digest region (a real row past `n_pub`, a forged word, a dropped index, a padding-row `MULT_READ`, a forged `H_PUB`, a mismatched height, a read hidden behind padding, prefix holes, index skips, disagreeing repeat reads, the digest-side C1 witnesses, and the pubdigest over-declare witness the final review named), and 6 in `tests/sbpf_abi.rs` (15 → **21**, the canonical `input_hash` and the region's refusals), with the remaining 7 spread over `tests/e2e.rs`, `tests/tables.rs`, `tests/emulator.rs`, `tests/isa.rs` and `tests/asm.rs`. Nine mandatory tables (ten/eleven with the optional hash chips), sixteen buses, `pv::NUM` 26 → 34, `tables::cpu::col::WIDTH` 224 → 275, `verifier_key` a 6-tuple. Every proof pays the segment whether or not its guest reads one: a keccak-free tier-10 `fib(10)` proof at `FriProfile::Test` grew ~8 %, 275 916 → 298 791 bytes, which is the mandatory-instance design's price and is carried in `tests/e2e.rs`'s own constant. The sBPF guest's ELF moved from the private tape to the segment and `program_hash` left its output digest: **1 753 945 → 694 498 cycles, 2 368 → 30 compressions, `sha256_log_height` 18 → 11, unprovable → `Tier(20)`** (`docs/04-guests.md`). **This is a hard fork for proofs** — set-5 proofs do not verify against a set-6 verifier — and the fullnode is not re-vendored by it. Both of `deploy/sync-zkvm.sh`'s two patches need extending first: the `verifier_key` exact-signature anchor (a sixth parameter now, and the script aborts loudly on it) and the `notes::domain` inlining, which must gain `PUB` alongside `HC`/`IN` or the synced node does not compile. `pv::NUM` rides along in the rsync and needs no anchor — see "Vendoring, as of constraint set 6" below |
| Phase Z | Fully shielded pool, zkVM side (`docs/superpowers/specs/2026-09-11-shielded-pool-design.md` §12): looped `MERKLE_VERIFY`, `u64` amounts, the 2-in-2-out `bundle` guest with dummy inputs and `u64` fee/burn conservation, ledger admission and viewing over bundles | `bundle` proves and verifies at a measured tier; every §13 cheating scenario is rejected (structurally or by the STARK); a party's or a transaction's viewing key opens exactly its bundle rows | **done** — the suite stood at 167 tests (166 pass, 1 pre-existing ignored) when phase Z landed; M4.2's 38 took it to 205, the 2026-09-12 audit port's further 18 to 223, and M4.3's 54 and M4.4's 93 (less the five `tests/isa.rs` tests both claim) to 365, and constraint set 6's 30 to 395. Phase Z added 30 of them across Tasks 1–4, 28 in `tests/bundle.rs`, and the 256-bit-`SpendKey` follow-up one more in `tests/viewing.rs` (`docs/06-viewing-keys.md`'s "The `bundle` relation" and "Ledger admission for bundles") |

M1's exit criterion as actually delivered is slightly broader than the
original wording: the demo and test suite exercise four guests, not three,
because `balance_check` is the crate's canonical "confidential computation"
example and earns its place alongside the three original correctness
guests.

M2's exit criterion as actually delivered is narrower than the original
wording: the six-task implementation plan (`docs/`'s M2 design spec) scoped
sub-word memory, the RV32M extension, and three infrastructure sub-tasks
(verifier-key cache, FRI retune — since reverted, byte-table split) as M2.1–M2.6, and marks
the milestone done on that basis — every guest in `guests::all()` is still
written directly against `src/asm.rs`'s mnemonic helpers, not compiled with
an external RISC-V toolchain. The flat-binary loader and a `READ_INPUT`
binding firmer than "a prover-chosen witness value, unconstrained across
repeated reads of the same index" (`docs/01-isa.md`'s syscall table,
`docs/03-privacy.md`) were part of M2's original aspirational scope but not
of the six-task plan that was actually built; they remained open, carried
forward rather than blocking this milestone's "done" status, until M4.1
closed both (`docs/superpowers/plans/2026-09-11-zkvm-m4-1.md`:
`Program::from_flat_binary`/`guest-sdk`/`guests-compiled/`, and
`READ_INPUT` bound to the salted commitment `H_IN`).

Phase Z is a separate, parallel track from M4, not part of its EVM/sBPF
scope: it is the zkVM half of the fully shielded pool, and it is finished at
the boundary of this crate. The next phase, **S1**, is the fullnode half — a
real `Bundle` transaction wire format, mempool admission, storage, RPC and
wallet — and is deliberately out of scope here; so are the fee and burn
*destinations* (S2/S3), which is why `Ledger::fees_collected`/`burned` are
running totals with nothing attached to them.

**v0.4** is a separate track from S1/S2/S3, approved 2026-09-18 alongside the fullnode's v0.3 RPC
work: `rand-guest`, the guest toolchain (piece 1 of 3, `docs/superpowers/specs/2026-09-18-rand-guest-toolchain-design.md`),
is done through Task 7; the `sbpf2rv` and `evm2rv` RV32 translators (pieces 2 and 3) have not started.

## Plan errata — M4.4 constants the implementation had to correct

Four numbers the M4.4 plan fixed in advance turned out to be wrong once the real
SPL Token ELF was in front of the loader. None is a design change; each is a
constant the plan could not have known, recorded here so the plan is not read as
the authority on them. Design spec §5.1 items 6–8 carry the full reasoning.

1. **Stack frames are Solana's 4 KiB, not the plan's 512 bytes.** The plan sized
   64 × 512 B to fit a 1 MiB guest, reasoning that SPL Token's `process_transfer`
   "uses well under that". It uses no nested frame *at all* — the release build
   inlines `entrypoint::deserialize`, `Processor::process` and `process_transfer`
   into one function — but that single frame is around 2 KiB, so with 512-byte
   frames the program faults on its **first instruction**, 1 560 bytes below the
   stack region's base. A frame size is part of the ABI a program was compiled
   against, not a budget the host may pick. `sbpf-core` keeps the plan's 32 KiB
   stack and reduces the depth: `STACK_FRAME = 4096`, `MAX_CALL_DEPTH = 8`. The
   measured frame-depth high-water mark for a `Transfer` is **0**.
2. **`MAX_INPUT_BYTES` is 49 152, not 16 384.** The *aligned* format
   `solana_program::entrypoint::deserialize` reads skips
   `MAX_PERMITTED_DATA_INCREASE = 10 240` bytes of realloc headroom after **every**
   account's data, unconditionally, so it cannot be trimmed: an account costs
   ~10 336 bytes plus its data. A three-account `Transfer` is 31 401 bytes and the
   four-account exit fixture is 41 825 — the plan's cap could not have held its own
   exit test. The input-vector *layout* is unchanged; only the cap moved, and it
   costs `.bss` rather than cycles.
3. **The loader's "a `call imm` with `src != 0` is refused" rule rejected the real
   file.** The toolchain marks **every** `call imm` with `src = 1` — eBPF's
   `BPF_PSEUDO_CALL`, "the immediate is a slot-relative target" — which is the
   inverse of `sbpf-core`'s own marker (`src = 1` means syscall). All 158 call sites
   in the committed ELF are `src = 1`: 141 unrelocated pc-relative calls and 17
   relocated syscalls. `elf::load` now normalises the file's marker away *before*
   applying relocations, leaving the relocation pass as the only thing that ever
   sets `src = 1`; any other `src` is still refused.
4. **The SPL Token program is not a `BPFLoader2` program.** The plan's one-line
   fetch assumed the account data *is* the ELF. `TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA`
   is owned by the **upgradeable** loader; its 36 bytes are an
   `UpgradeableLoaderState::Program`, and the ELF is 45 bytes into a second,
   program-data account. Its upgrade authority is `None`, so the bytes are immutable
   in practice — the property the plan's reasoning actually needed.
   `guests-compiled/sbpf/programs/SPL_TOKEN.md` records both RPC calls and the slot.

## Known deviations from the whitepaper

These are the design spec's own §12 list, restated with their current
status, plus one deviation introduced during implementation and since
reverted (6), and one refinement that is not a deviation from the whitepaper
but is worth flagging alongside them (8); 7 is M4.3's measured tier.

1. **Closed in M3.4.** `hc` is now an ordinary public value (`pv::HC0..HC7`),
   computed in-circuit by `cpu`'s digest-row prefix over the program table
   (now a witness trace, `docs/02-tables-and-buses.md`'s in-circuit
   decoder) with the Poseidon2 chip, exactly as the whitepaper wants: one
   universal verifier key per (tier, declared program/input/keccak/sha256 heights)
   (`Machine::verifier_key`, program-*content*-independent), `hc` supplied by the caller as an input to
   `Machine::verify(hc, proof)` rather than baked into a per-program
   `CommonData`. What the whitepaper's "public input" framing does *not*
   itself provide — a hiding salt for `hc`, so a verifier who cannot
   already guess the program cannot test candidates against it — remains
   open; see `docs/03-privacy.md`'s "`hc` is now an in-circuit digest"
   section for exactly what changed and what didn't, and "A hiding program
   commitment (ZKVM-108)" there for the design that closes it at the next
   constraint set (host arithmetic in `src/program_commitment.rs`; no
   constraint is built).
2. **The gas tier is public per proof, not just as a batch histogram.** A
   STARK's own size already reveals its trace height, so hiding the tier
   index buys nothing at the single-proof level; the whitepaper's
   per-batch histogram claim is a property of the aggregation layer
   (milestone 4+), not of one proof.
3. **Zero knowledge is statistical, not perfect**, because Plonky3 0.7's
   hiding FRI PCS is statistically zero-knowledge by its own admission
   (`p3-batch-stark-0.7.0/src/prover.rs:469`). See `docs/03-privacy.md`.
4. **The transcript hash is Poseidon2, not SHA3-384/BLAKE3-384.** The
   whitepaper's production transcript uses the latter; Poseidon2 is used
   here because Plonky3 ships it natively and recursion (a later
   milestone) will need an arithmetization-friendly hash regardless.
   Swapping it is a config change, covered by the whitepaper's own
   crypto-agility registry, not a rewrite.
5. **Recursion and per-batch aggregation are out of scope** until
   milestone 4 or later; this crate proves and verifies individual guest
   executions only.

   - **Done (M4.2, Task 6): the keccak table is optional per proof.** As
     first built, the keccak table was in every proof including proofs that never
     used it — its height floored at one 32-row padding block, and a 2 612-column
     table costs about 1.91 MB of the production profile's FRI leaf openings
     regardless of how many rows it has (~705 KB at the 27 queries M4.2
     measured, 80 since the 2026-09-12 revert — `docs/03-privacy.md`'s M4.2
     measurement), which would have pushed a ~300 KB shielded bundle proof past
     the node's 1 MiB cap. A proof now declares `keccak_log_height = 0` when its
     guest makes no `KECCAK` call, and `machine::chips` returns eight chips
     instead of nine (every count in this bullet is M4.2's own; constraint set 6
     later appended a mandatory `public` table, so each is one higher today).
     The machine-shape consequences are all handled: the keccak
     instance is last, so no other chip's index moves (the `i == 1`
     public-values slot included); `Traces::as_slice` returns eight or nine
     traces; `log_ext_degrees` emits eight or nine degree bits, so the existing
     equality check also pins the instance count; `klh = 0` is a distinct
     `KeyCache` key. Keccak-free proofs are back to their pre-M4.2 size, and
     M4.3's SHA-256 chip can follow the same pattern.

   - **Done (M4.4): the SHA-256 chip follows it, and independently.**
     `tables::sha256` (466 main + 10 preprocessed columns, one row per round in
     64-row blocks) joins the batch as `Chip::Sha256`, last in `chips()` order, on
     exactly the same optional-per-proof terms: `sha256_log_height = 0` means no
     instance, the `SHA256` bus then has no provider, and a cpu row claiming
     `SYS_SHA256` cannot be proved. The two optional tables are independent, so a
     batch carried eight, nine or ten instances (nine, ten or eleven since
     constraint set 6 appended the mandatory `public` table) and the verifier key's cache key
     grows to `(tier, program, input, keccak, sha256)` — a 6-tuple since that
     set added `public_log_height` — an arity change the
     fullnode's `deploy/sync-zkvm.sh` anchors on, so it is part of the next
     re-vendoring rather than of this milestone. Measured cost of carrying the
     table: +92 307 bytes at `FriProfile::Test`, +400 563 at the production
     profile (against keccak's +1.91 MB), which is the ~0.21 ratio the 476/2 711
     column ratio predicted — `docs/04-guests.md`'s "plan the column budget
     against that number", confirmed.

6. **Reverted 2026-09-12 on audit: the production FRI profile.** M2.2
   retuned `FriProfile::Production` from the whitepaper's 80 queries /
   blowup 8 / 20 PoW bits down to 27 queries, on the ethSTARK *conjectured*
   bound `log_blowup·num_queries + query_pow_bits >= 100` (`3·27+20 = 101`)
   — a deviation from the paper's parameter table (Draft 3, Part III) that
   was entered here as a justified one. The 2026-09-12 zk audit (finding
   ZM1) showed it was not: the conjectured bound is not the only one the
   paper's choice is holding up. The *proven* proximity-gaps floor is ~86
   bits at q=80/g=20 and falls roughly linearly with the query count, so 27
   queries leaves ~42 proven bits (a provable 100 needs q=97 or g=34), and
   the paper's own Part III reconciliation had already weighed exactly that
   trade and kept q=80. `Production` is back to 80/8/20; the deviation is
   closed by reversion, not by argument. Cost, re-measured on `guests::fib`
   before and after: proof size 435 529 → ~1 200 000 bytes at tier 10 and
   460 441 → ~1 258 000 at tier 12, with prove and first-verify time
   unchanged within noise (`docs/03-privacy.md`'s profile table). Two
   consequences for whoever ships it: a 27-query proof and an 80-query
   verifier reject each other in both directions, so this is a hard fork for
   proofs and a fleet must run one build; and a production proof no longer
   fits the node's 1 MiB proof cap (a hash-table-free tier-10 proof is ~1.20 MB,
   a sha256-carrying one ~1.60 MB, a keccak-carrying one ~3.11 MB), which has to
   be raised in the same change.

7. **M4.3's ERC-20 `transfer` proves at tier 18, not the plan's ≤ 16 (spec
   estimate 14).** `TIERS` is `[10, 12, 14, 16, 18, 20]`, so 18 is the next rung
   above 16 and tier 16 would need the whole call under 65 535 cycles — half of
   what it costs — rather than a trim. The exit criterion was a target, not a
   soundness property,
   and the measured cost is 121 638 executed cycles (126 373 with the program-
   and input-digest prefixes). Where it goes, measured per fixture rather than
   estimated: ~51 200 cycles in the interpreter itself (~250 opcodes of dispatch
   and software 256-bit arithmetic), ~27 300 in the four 32-level Merkle walks
   (132 17-word `POSEIDON2` calls at ~207 cycles each), 23 021 in the code
   (decoding 1 296 bytes, the jumpdest scan, `codehash`), 13 922 of per-call
   fixed overhead, 6 342 decoding the two witnesses, and 4 735 in the two digest
   prefixes. Local levers already took it from 224 212 total cycles to 126 373
   (`Interpreter::new` clears only the memory a previous run dirtied, −51 606;
   the sponge calls marshal a 17-word buffer in place, ~850 → ~207 cycles a
   call; the input cursor stores bytes rather than calling `memcpy` per word,
   ~29 → ~4 cycles a byte), and `opt-level = "s"`/`2` were measured and rejected
   — both trade fewer program-digest rows for more execution and come out worse.
   The named follow-ups, in the order they pay: a looped `MERKLE_VERIFY`-style
   storage syscall or a wider sponge rate, then the dispatch loop, then a
   modular-arithmetic chip (`docs/04-guests.md`'s "The `evm` guest"). Nothing
   about the milestone's correctness depends on the tier: the exit test pins the
   measured number, so a regression is a failing test rather than a bigger
   proof. The one thing the tier costs in practice is that the transfer's *proof*
   does not fit the development machine: three attempts reached ≥ 28.5 GB resident
   before the OS killed them on a quiet 48 GB laptop, and the resident set was still
   growing, so a **≥ 64 GB** machine is the safe requirement. That is why the
   transfer's proof is an `#[ignore]`d test and the in-suite EVM proof is a smaller
   call through the same binary at tier 16 (774 KB, 438 s to prove). It is also the
   sharpest argument for the follow-up: under tier 16 the whole thing fits a laptop.

8. **Selector refinement (not a deviation, a design choice).** The design
   spec described one flag per mnemonic; the implementation pre-decodes
   23 semantic selector fields instead (`docs/01-isa.md`; M2.5 grew this
   from 18 to 23 by replacing the single `is_load`/`is_store` booleans with
   a one-hot per load/store width plus a `signed` flag). Same trust model
   — the CPU still never decodes a bit — fewer columns than one-per-
   mnemonic, and constraints that read as "if `is_lb+is_lh+is_lw` then …"
   rather than sums over every individual instruction's own flag.

## The next constraint set: what it must carry

The 2026-09-27 zkVM and rVM reviews left a handful of findings whose fix is a change to the AIR, to
a syscall's semantics or to the verifier keys — each a chain cut, none a same-chain release (chain
15's keys, program digests and proof format are unchanged by everything on this branch). They are
collected here with the exact rule each needs, so the next set is one cut, not five. Where a gap
can be shown today it is pinned by a **failing-by-design** test in `tests/next_constraint_set.rs`
(`#[ignore]`d with the reason; `--ignored` runs them and they fail), which loses its `#[ignore]`
and passes when the rule lands.

1. **ZKM-1 / ZKH-2 — input and public words are 32-bit in the AIR** (with ISA-2, ARITH-3, COV-4).
   **Done on `feat/cs7-range-pad-isa`**: `WL0..3` on both tables as below, and — beyond this rule,
   at the lead's call — the salt row's four lanes too, for free: they reuse the write-back rows'
   `HVL0_0..15` limb columns (`IS_HASH_OUT + IS_SALT` gates them), 16 `RANGE8` lookups a proof, no
   new cpu column, so `H_IN` commits only to a salt that four `u32`s reproduce.
   Today the `input` table provides `(IDX, WORD)` and nothing range-checks `WORD`, and the cpu's
   `SYS_READ` row receives it into `C`, which is range-checked nowhere on that row either: a guest
   can be handed `2^32 + 5` for `5` consistently in every table
   (`a_non_u32_input_word_is_refused_by_the_air`). The rule, in `tables::input`: four byte limbs
   `WL0..WL3` beside `WORD`, and
   `IS_REAL · (WORD − (WL0 + 2^8·WL1 + 2^16·WL2 + 2^24·WL3)) = 0` with
   `RANGE8.lookup_key([WL_k], IS_REAL)` for `k = 0..4` (and `WL_k` pinned to zero on padding, the
   table's invariant 1). The `public` table's `WORD` gets the identical four limbs and rule. Cost:
   4 columns and 4 `RANGE8` lookups per real row of each table. The salt words the `IS_SALT` row
   absorbs (HCS-5) need nothing: the salt only has to hide, and `H_IN` binds whatever field
   elements were absorbed. Output words are already refused above `u32::MAX` by `Machine::verify`
   (ZKA-1, `check_public_values`); moving that in-circuit (four limbs on the `SYS_WRITE` row's
   `MEM_VAL`) is what would let `recursion/src/aggregate.rs` drop the `expect` it keeps on it.
2. **HCS-4 — `POSEIDON2` binds the message length.** The syscall's sponge starts from the zero
   state, so within the first rate block `[a]` and `[a, 0]` collide and `[]` is the zero digest
   (`poseidon2_binds_the_message_length`; ZKH-3 documented it, `docs/01-isa.md`). Changing
   `POSEIDON2` itself would change every note commitment, nullifier, Merkle root and program
   digest `hc` a chain holds, so the rule is a **new syscall**, `POSEIDON2_LEN = 7`, beside the
   old one: a `SYS_HASH_LEN` selector whose group start seeds the capacity instead of zeroing it —
   where `tables::cpu` today asserts `SYS_HASH · n(HS0 + i) = 0` for `i = 0..8` (the first absorb
   row's input state), the new flag asserts `SYS_HASH_LEN · n(HS0 + i) = 0` for `i ∈ {0..3, 5..7}`
   and `SYS_HASH_LEN · (n(HS0 + 4) − n(HASH_N)) = 0` — the length in capacity lane 4, the rest of
   the group unchanged (the `POSEIDON2` bus and chip permute whatever state they are given).
   `hash::sponge_hash_len`, the emulator and `guest_sdk::poseidon2_len` follow; the test above
   then targets the new syscall. **Done on `feat/cs7-range-pad-isa`**, with one addition the test
   forced: seeding lane 4 alone leaves `POSEIDON2_LEN([])` the zero digest (no block, no
   permutation, and the digest is rate lanes 0..3), so an `n = 0` call absorbs **one empty block**
   — `SYS_HASH_LEN · (1 − n(IS_HASH)) = 0` (never straight to write-back) — and the blanket
   "lane 0 is active on every absorb row" becomes "on every absorb row but a group's first"
   (`IS_HASH · (1 − ACT0) · HASH_IDX = 0`), with `SYS_HASH · n(IS_HASH) · (1 − n(ACT0)) = 0`
   keeping a plain `POSEIDON2` group's first block non-empty.
3. **VERIFIER-1, the rVM half.** `research`'s `Machine::verify` refuses a non-zero commit-phase
   proof-of-work word since this branch (`check_commit_pow_witnesses`); the aggregate program still
   reads each word and drops it (`recursion/docs/00-recursion-vm.md`, segment 7). The next
   aggregate program version constrains each to zero (one `assert_eq` against a zero constant per
   FRI round, in `programs/rv32.rs`'s FRI-commits loop) — a new aggregate program digest, which
   is why it waits for the version bump rather than riding a same-chain release. *Landed in
   constraint set 7 (`feat/cs7-rvm-pow`, integrated on `feat/cs7`)*: the FRI-commits loop asserts
   each word zero (trap `commit pow witness[r]`), the host replay and the rVM's own native
   verifier refuse it too, and every program pin was re-measured on the integrated tree.
4. **HCS-1 — stable verifier-key salts.** Switch every key config from `StdRng::seed_from_u64(
   KEY_SEED)` to `key_derivation_v2` (research and recursion; the module comment is the recipe),
   re-pin `tests/verifier_key.rs` in both crates, and the three exact `rand` pins can go back to
   carets. *Landed as constraint set 7 (branch `feat/cs7-logup-blind`)*: one salt type,
   `key_derivation_v2::SaltRng`, with a key source (the v2 stream, from `research`'s labels or the
   rVM's own `rvm/key/*`) and a proving source (`StdRng` from OS entropy — proving blinding, where
   `rand` belongs); `SeedableRng::from_seed` is always the v2 stream, so p3's clone-by-reseed never
   routes a key through `StdRng`. `rand-zkvm-cuda`'s `HidingMmcs` is generic over the generator so
   the backends salt identically. The exact pins were kept (they now decide only proving's salts).
5. **ISA-4 / ISA-5 — the decoder's two tolerances** (`docs/01-isa.md`, "Deliberate deviations"):
   `JALR` clears bit 0 of its target and requires `funct3 = 0`. Each changes what the in-circuit
   decoder accepts, so it is a program-table change and rides the cut. **Done on
   `feat/cs7-range-pad-isa`**: `Instr::decode` and the program table's `JALR` flag require
   `funct3 = 0`; the emulator jumps to `(rs1 + imm) & !1` and the cpu's `JALR_B0` column is the
   dropped bit (`NEXT_PC = ALU_OUT − JALR_B0`, sound by the next row's fetch). No in-tree
   program's words or digest change.
6. **INT-2 / GV-1 — blind every LogUp terminal; floor every table at `2^7`.** *Landed as
   constraint set 7 (branch `feat/cs7-logup-blind`).* Each table's published LogUp terminal was a
   checkable function of its trace (a call's private words, a bundle's dummy slots —
   `tests/logup_blind.rs` replays the challenges and predicts them exactly on the old tree). Every
   instance now carries five columns after its own (`tables::blind`, appended by `machine::Chip`):
   a two-coordinate value sent and one received on a new `BLIND` bus, first row only (a `FIRST`
   selector column is the multiplicity), the honest
   prover cycling fresh values through the batch so each terminal moves by a uniform element of
   `F_{p²}` while their sum stays zero. The verifier's floor on every declared table height is now
   `MIN_PRIVATE_TABLE_LOG_HEIGHT` (program, input and public `MIN_LOG_HEIGHT` 7; keccak and sha256
   at least 7 when present), because a table's running-sum columns are opened like its main
   columns. `docs/03-privacy.md`, "LogUp terminals are blinded", has the argument; the chain side
   derives a call's program height from `program_log_height` (floored), and a deploy's pc window
   has to cover the floored table (PCW-FLOOR).
7. **ZKVM-202 — gas weights that track committed cells** (fullnode #167). *Closed in constraint
   set 11* (below). `MODQ_GAS = 168` was derived from the chip's block alone; counted with the
   memory rows the chip sends and with blind and LogUp columns, `DOT4` bought 1.57 and `MSUB4`
   1.81 times a plain cycle's cells per gas, `KECCAK` 0.70 and `SHA256` 0.77, an absorb row 1.24.
   Not a finding that breaks soundness, so under the owner's October ruling it did not force a
   cut; the November ruling adopted the counted weights at the next set, hash weights included.
   `docs/07-gas.md` has the method and the count; `tests/gas_cells.rs` holds every priced row to
   it, with `KNOWN_MISPRICED` empty.

## ZKVM-107: the round-constant switch-over

The Poseidon2 round constants every hash here uses are still the development draw
(`src/poseidon2_constants.rs`, "RandZK"). Their replacement is chosen and committed, and **not in
use**: `src/poseidon2_constants_next.rs` holds the 86 constants the Poseidon paper's Grain LFSR
gives for this permutation's own parameters (prime field, `x^7`, `n = 64`, `t = 8`, `R_F = 8`,
`R_P = 22`). `src/poseidon2_grain.rs` is the generator, `tools/poseidon2_grain/grain.py` a second
implementation in standard-library Python, and the table equals the one `p3-goldilocks 0.7.0`
ships as `GOLDILOCKS_POSEIDON2_RC_8_*` (tests in `poseidon2_constants_next.rs` check all three).
The round numbers, the S-box and both linear layers are the ones the `poseidon2` chip's AIR
already implements, so the switch changes preprocessed constants and no constraint.

Why it is not behind a switch today: this crate has one `CONSTRAINT_SET` number and one table,
and the table is read by value in places a cargo feature in this crate cannot reach — the
`#[path]` copy in `rand-zkvm-cuda`, the rVM's verifier program and its Poseidon2 precompile
(`../recursion`), the published guest digests, the wallet and the full node. Carrying two live
tables would mean a second set of every pin below for a configuration nothing runs. So the
candidate is data plus tests, and the cut is the list below, done in one change with the other
changes waiting on a new set (ZKVM-108, ZKVM-111, ZKVM-112, ZKVM-113).

What the switch moves — every Poseidon2 output, so: every program digest `hc`, every input and
public digest, every Merkle root and FRI commitment, every verifier key (the preprocessed
commitment and the `key_derivation_v2` salts, which are a Poseidon2 stream), note commitments,
nullifiers, viewing-key derivations, storage roots, and the genesis hash. It can only ship as a
new genesis.

The cut, in order:

1. `src/poseidon2_constants.rs`: replace `INITIAL`, `INTERNAL`, `TERMINAL` with
   `poseidon2_constants_next`'s tables (or make that file the table and delete the old one);
   delete `the_table_is_the_seeded_draw`, move the Grain and Plonky3 tests over, replace the
   three known vectors with the candidate's (`KNOWN_VECTORS` there). `PERM_SEED` then names
   nothing: rename the key `rand-zkvm-cuda`'s engines take (`constants::permutation(seed)`,
   `CpuHashEngine::new`, `GpuProver::probe`, `gpu/ntt.rs::DEFAULT_PERM_SEED`,
   `recursion/src/machine/backend.rs::PERM_SEED`) or keep it as an opaque tag, and say which.
2. `machine::CONSTRAINT_SET`: bump, in the same commit.
3. `rand-zkvm-cuda`: it compiles the table in by `#[path]`, so it follows step 1 with no edit;
   re-run `tests/poseidon2.rs` (host twin and mock driver) and, on a device, `gpu_hw.rs`.
   `gpu-kernels` takes the constants as an uploaded buffer and has none of its own.
4. `../recursion`: rebuild the verifier program (its transcript and Merkle code hash with the
   same permutation through the POSEIDON2 opcode and precompile), then re-record
   `tests/fixtures/pins.json` and regenerate the proof fixtures (ZKVM-102's script).
5. Re-pin in this crate: `tests/verifier_key.rs` (every key), `tests/key_derivation_v2.rs`,
   `tests/hash_domains.rs`, `tests/key_blob.rs`, the `hc` values in `tests/` and
   `../guests-compiled/bin/*.sha256` consumers, `../evm2rv` and `../sbpf2rv`'s published `hc`s.
6. Guests: no guest binary changes (a guest hashes through the syscall, not in software) but
   every published `hc` of one does. Check with `rand-guest check`.
7. Downstream, at the same genesis: the full node's vendored copy and its pins
   (`CIRCUITS_PIN`, admitted keys, genesis), the wallet's WASM and its pinned digests, randscan's
   WASM, the bridge's note commitments, durian's program pins.
8. Docs: remove the placeholder entries (`AGENTS.md` "Known development placeholders",
   `03-privacy.md` on the constants, `06-viewing-keys.md`), and update
   `02-tables-and-buses.md`'s description of where the constants come from.

Not decided here: whether to keep the internal diagonal `MATRIX_DIAG_8_GOLDILOCKS` (Plonky3's)
— it is not a round constant, it is unchanged by this switch, and it is what upstream's
permutation uses with these constants, so keeping it keeps the two identical.

## Constraint set 8: the gas meter

Not a finding from the 2026-09-27 reviews above — a separate driver, the fullnode's gas design
(spec 2026-09-28, "Phase 0/1" of chain 18's plan: pay per instruction in RAND on a declared,
in-circuit-proven bound). Branch `feat/cs8-gas`, seven commits (`4d448ec`, `f0dc825`, `13dc769`,
`6ec5a5b`, `6ad7d74`, `f95a1ce`, `6d4f124`) plus the final review's fix wave. What it carries:

- **`pv::GAS`** (`tables::cpu::pv`), a 35th public value (`PUB0 + 8`, `pv::NUM` 34 → 35) — the
  header's declared gas ceiling. `gas::gas_max(tier, keccak_log_height, sha256_log_height)` is
  `(2^t − 1) + 2^(t−2) + 191·(2^klh/32) + 63·(2^slh/64)`: the tier's cycle budget, plus `+2` for
  each of the at most `2^(t−3)` `POSEIDON2` absorb rows the poseidon2 table's `2^(t+2)` rows can
  hold (one 32-row permutation each), plus the weight of every permutation and compression block
  the declared keccak/sha256 heights could hold. It is the header's ceiling because each term is
  the most its row kind can spend under that header, so no run the header admits costs more. (The
  first cut omitted the absorb term, and a tier-10 run of 30 absorbs and 1 016 rows spent 1 078
  gas against a 1 023 ceiling — refused `GasLimitBelowRun` with no limit that made it provable;
  the final review's fix added the term.) The tier is clamped to `[10, 20]` before any shift, and
  `check_public_values` refuses a tier outside `TIERS`. `Machine::verify`
  refuses `pv::GAS > gas_max(...)` natively (`VerifyError::GasLimit`), before any verifier key is
  built — the same cheap-before-expensive placement as the tier and height checks beside it.
- **`gas::gas_of`**, the native meter over an execution (`Program`, inputs, public words, the
  `CycleEvent` trace): the digest-prefix rows (program, input, public — each counted once, never
  per cycle) plus `row_gas` per cycle — 1 gas for an ordinary row, `KECCAK_GAS = 192` for a
  `KECCAK` row, `SHA256_GAS = 64` for a `SHA256` row, `POSEIDON2_ABSORB_GAS = 3` for a `POSEIDON2`/
  `POSEIDON2_LEN` absorb row (a row is never charged more than one of these). `gas_of` is what the
  prover's own run costs; `gas_max` is the most a header could ever cost. Used only off-circuit
  (fee computation, `ProveOptions.gas_limit`'s own floor) — the circuit charges gas independently,
  below.
- **The cpu table's `GAS` column and its four `GD0..3` halt-row limbs** (`col::WIDTH` 277 → 282):
  `GAS = 1` on row 0 (a digest row); on every transition into a real row, `GAS` grows by exactly
  `gas_of`'s weights (degree 2); on the one `HALT` row, the slack `pv::GAS − GAS` is held,
  byte-limbed, in the witness-only columns `GD0..3` and range-checked (`RANGE8`,
  `Count::bounded(SYS_HALT, 1)`) — never published, only proven non-negative — so the declared
  ceiling is provably at or above the run's own gas without the run's gas itself ever appearing as
  a public value; the limbs are pinned to zero on every other row, padding included. Four limbs
  are enough because the native check above already bounds `pv::GAS` under `2^32`.
  `docs/02-tables-and-buses.md`, "Constraint set 8: the gas meter", has the constraints in full;
  `docs/01-isa.md`'s syscall table gains a gas column built from these same weights.
- **`ProveOptions.gas_limit: Option<u64>`** — a prover may declare any ceiling from its own run's
  gas up to the header's `gas_max` (refused outside that range, `GasLimitBelowRun` /
  `GasLimitAboveHeader`, before the cpu trace is built — `keccak_trace`/`sha256_trace` are built
  first, since the limit needs their declared heights); `None` (the default, unchanged behaviour)
  declares the header's own ceiling. `docs/03-privacy.md`, "What a proof leaks", has the leakage
  argument: the default leaks nothing beyond the tier and hash heights already do, and a coarser
  declared bucket leaks `log2(bucket)` fewer bits than the exact count would.

**Measured proof-size deltas** (`FriProfile::Production`, `measure_production_profile_at_tier_10_and_12`,
two runs each side, run-to-run noise ≈ ±6 KB — five cpu columns (`GAS`, `GD0..3`) and four
`RANGE8` lookups added, no new preprocessed table):

| Shape | Before cs8 | After cs8 | Change |
|---|---|---|---|
| tier 10, no hash chip | 1 368 874 / 1 363 178 B | 1 367 083 / 1 368 939 B (re-measured: 1 370 443 / 1 367 371 B) | ≈ +2 KB, +0.15 % |
| tier 12, no hash chip | 1 419 308 / 1 426 027 B | 1 428 781 / 1 432 365 B (re-measured: 1 431 181 / 1 431 981 B) | ≈ +8 KB, +0.56 % |
| tier 10, one keccak block | 3 280 413 / 3 269 053 B | 3 284 155 / 3 284 413 B (re-measured: 3 286 141 / 3 286 941 B) | ≈ +10 KB, +0.29 % |

The re-measured pairs are this task's own run, reconciling within the ±6 KB noise band against the
pair the column landed with (`13dc769`'s commit body). All four verifier keys' `common` digest
moved (the four new `RANGE8` lookups); no `commitment` digest moved (no new preprocessed periodic
table) — `tests/verifier_key.rs` re-pinned, in the same shape as constraint set 7's own RANGE8
widening. **Every verifier key changed; ships only with a chain cut** — chain 18 in the fullnode's
plan, alongside Phase 1's per-instruction fee schedule.

## ZKVM-112: a proof-declared poseidon2 table height (opt-in, `next-set`)

The poseidon2 table is `2^(t+2)` rows at every tier whether or not the guest hashes. The next
constraint set lets the proof declare its height, as it already declares the program, input,
keccak, sha256, modq and memory tables'. That is built, behind the cargo feature `next-set`
(`src/next_set.rs`, `tests/next_set.rs`), and **not part of the live machine**: without the
feature nothing is compiled, and with it `machine::Machine`, its proofs and its keys are the
same. The only edits to `machine.rs` are three functions that take the poseidon2 height as an
argument (`chips_at`, `log_ext_degrees_at`, `prove_traces_at`); every current-set caller passes
`tier.poseidon2_height()`, and `tests/verifier_key.rs` / `tests/key_blob.rs` pass unchanged.

What the opt-in set does:

- `next_set::Proof` is the current proof plus one header byte, `poseidon2_log_height`.
- Admitted heights are `t + 2, t, t − 2, …` down to the private-data floor: `8, 10, …, t + 2`
  at the even tiers in `TIERS`, `(t − 4) / 2` shapes per tier (8 at tier 20) where every height
  from 7 would be `t − 4`. A coarser set means fewer verifier keys, at the price of a table up
  to four times taller than the run needs.
- `next_set::Machine::verify` range-checks the declared height with the other declared
  heights, before the degree-bits comparison and before any key build
  (`a_height_outside_the_admitted_set_is_refused_before_any_key_is_built` counts zero builds
  over every non-admitted `u8`).
- The height is the eighth component of the key tuple. At `t + 2` the key is the current key
  and a proof made there verifies on the live machine, so the chip is the same chip.
- The poseidon2 AIR is untouched; only the table's height and its preprocessed trace's height
  change.

Measured (committed main-trace cells; no blind, LogUp or preprocessed columns):

| guest | tier | permutations | poseidon2 table | main cells | change |
|---|---|---|---|---|---|
| `fib(10)` | 10 | 3 | 2^12 → 2^8 | 626 432 → 495 872 | −20.8 % |
| `poseidon2_demo`, 64 words (tier forced) | 12 | 62 | 2^14 → 2^12 | 2 468 096 → 2 050 304 | −16.9 % |
| ERC-20 transfer (compiled EVM guest) | 18 | 5 814 | 2^20 → 2^18 | 162 199 808 → 135 461 120 | −16.5 % |

The first two were proved and verified at `FriProfile::Test`; the ERC-20 row is a trace build
only (a tier-18 proof does not fit this machine). The poseidon2 table is 22.0 % of the ERC-20
run's main cells today, not the 30 to 40 % the review estimated, and the run cannot go below
2^18 because 4 910 of its 5 814 permutations are the program digest of the roughly 19 600-word EVM
guest: a large program pays for its own `hc` on every call. Peak heap and prove time were not
measured, and msauth was not measured at all.

Left for the cut:

1. Move `poseidon2_log_height` into `machine::Proof`, `Traces` and `VerifierKeyShape`, with the
   range check inside `check_declared_heights_with_modq`; bump `CONSTRAINT_SET`.
2. `gas::gas_max`: the permutation term can follow the declared height, as the keccak term does.
3. `../recursion`: `shape.rs` reads a seven-component tuple from an RV32 proof and
   `programs/constraints.rs` builds `chips(tier, …)`; both need the eighth component, and the
   rVM's verifier program then moves.
4. The key blob (`VerifierKeyBlob`), `Machine::has_cached_key` and the GPU / reference backends
   (`prove_on`).
5. Forgery tests in `tests/cheating.rs` for the new header field on the live path (the opt-in
   tests cover the header and the degree bits; nothing forges a trace at a short height).
6. Decide the step. 2 keeps keys few; 1 halves the worst-case over-allocation.

## Constraint set 9: the MODQ chip

Not a finding from any review: the private multisig's phase 3 (`docs/superpowers/specs/2026-10-11-private-multisig-design.md`
§7), designed in `docs/superpowers/specs/2026-10-11-rvm-modq-chip-design.md`. Dilithium2's ring
arithmetic over `q = 8 380 417` becomes a coprocessor, so a threshold-signature verification fits
a tier a prover pool can prove.

**What moved.**

- **`SYS_MODQ = 8`** with ops `NTT`, `INTT`, `DOT4`, `MSUB4`; `MODQ_GAS = 168`; the cpu table gains
  the column `SYS_MODQ` (`WIDTH` 282 to 283) and one `bus::MODQ` lookup.
- **The `modq` table**: 1 024-row blocks, 59 main + 16 preprocessed columns, AIR degree 3 and
  instance degree 4, 16 lookup groups in the machine. New buses `MODQ` and `MODQ_WIRE`. Optional
  per proof (`modq_log_height = 0` absent), appended after sha256 and before `public`.
- **API.** `Proof::modq_log_height` after `sha256_log_height`; the verifier-key tuple grows from
  6 to 7 (`(tier, program, input, keccak, sha256, modq, public)`); the legacy entry points keep their
  signatures and delegate with `modq_log_height = 0`, and `_with_modq` siblings take the eighth
  argument. `ProveOptions::min_modq_log_height` is the explicit floor.
- **Verifier-key blobs: export/install, format v1** (`Machine::export_verifier_key_with_modq`,
  `Machine::install_verifier_key`, `CONSTRAINT_SET = 9`; `docs/02-tables-and-buses.md`), so the
  fullnode ships the tier-18 `msauth` key instead of building it on 4 GB validators.
- **Measured effect** (this branch): Dilithium2 verification 880 102 cycles in software, 348 967
  with the chip, **80 572** with the dilithium-core trims (99 `KECCAK` permutations and 18 `MODQ`
  calls). The `msauth` guest at `M_MAX = 3` is 251 946 cycles at tier 18 (`docs/04-guests.md`).
- **Tests.** 22 `modq_*` cheating tests, each AIR-level forgery accepted with only its defence off and
  rejected with it on; the hooks sit behind the `cheating` cargo feature, `tests/common/modq_run.rs`
  is always compiled and `tests/common/modq_harness.rs` is gated; the two share one `run_raw_on`,
  generic over the modq AIR.

**Proof-size deltas (measured, tier 10).** Means of four runs each, bytes, `postcard` proof size.
Per-run sizes vary by about ±1% (the four Test "before" runs span 312 329 to 317 289 bytes; the
random H_IN salt and commitment randomness change the opened paths). Before = merge-base `c83b1c7` (no chip); after = this
branch with `modq_log_height = 0`; one block = a guest making one `NTT0` call (three `li`, the
ecall, halt; one 1 024-row block, memory table at its tier-10 floor 2^12, asserted), measured by `tests/modq.rs::measure_modq_proof_sizes_at_tier_10` (`--ignored`).

| Profile | Chip-free before | Chip-free after | one modq block, after | Chip-free delta | One block vs. before |
|---|---|---|---|---|---|
| Test (27 queries) | 315 265 | 317 330 | 350 329 | +2 065 (+0.7%, noise) | +35 064 (+11.1%) |
| Production (80 queries) | 1 368 675 | 1 372 580 | 1 521 236 | +3 905 (+0.3%, noise) | +152 561 (+11.1%) |

Runs (before Test / before Production / after Test / after Production chip-free / one block Test / one block Production):
312 329, 317 289, 316 361, 315 081 / 1 367 466, 1 362 603, 1 374 731, 1 369 898 / 316 810, 318 153, 316 617, 317 738 /
1 371 947, 1 374 636, 1 368 588, 1 375 148 / 351 017, 350 986, 349 864, 349 450 / 1 518 795, 1 519 884, 1 526 700, 1 519 564.
The chip-free deltas (+0.7% and +0.3%) are indistinguishable from run-to-run noise; they do not
confirm or refute the estimated +1 KB. A chip-bearing proof costs
about twice the estimated +75 KB at Production FRI (+153 KB measured, +35 KB at the Test profile).

**Every verifier key changed; ships only with a chain cut.** The cpu's extra column and lookup move
every key's `common` digest, chip-free shapes included (`tests/verifier_key.rs`, plus a fifth
shape, "tier 10, one modq block"). Program digests `hc` do not move. Old proofs do not decode (the
extra header byte). It is a hard fork, and the fullnode re-vendor is pending.

**Sync-zkvm steps (spec §6), at the cut.**

1. `deploy/sync-zkvm.sh` rsyncs `src/modq.rs`, `src/tables/modq.rs` and `tests/modq.rs` (keep
   `tests/modq.rs` free of `dilithium-core`; its docs check skips itself where `docs/` is absent).
2. Add `pub mod modq;` by hand to the fullnode's `crates/randprotocol-zkvm/src/lib.rs`.
3. The `verifier_key` anchor and the `notes::domain` patch need no change; assert it.
4. `ZkExecutor::decode_and_check` keeps the modq-free calls, so a modq-bearing proof is refused
   until multisig phase 4 switches the auth-proof path to the `*_with_modq` calls.
5. In `executor.rs` add `const NO_MODQ: u8 = 0;` beside `NO_KECCAK` and `NO_SHA256`, and pin
   `modq_log_height == 0` in every non-multisig program record, next to the keccak/sha256 checks.
6. `ProveOptions::pad_absent_hash_tables` does **not** pad the modq table: a chip-free proof keeps
   `modq_log_height = 0`, and only the explicit `min_modq_log_height` floor declares an idle one.
7. `TIERS` does not change. Re-check its client-side users (`clients/core/crates/wallet-core`,
   and the vendored `randprotocol-client` and `randprotocol-rvm` under `clients/core/vendor/fullnode`):
   they need only the new `Proof` field and the re-pinned keys.
8. Re-pin `CIRCUITS_PIN` (in the fullnode), the verifier-key digests and
   `aggregate_program_digest`. Mirror `MODQ_GAS` in the fee schedule.

**Final-review handoff (11 steps, the complete re-vendor list for the cut):**

1. Vendor `dilithium-core` (add to `for CRATE in evm-core sbpf-core` + the uncommitted check + a path dep in `crates/randprotocol-zkvm/Cargo.toml`).
2. `lib.rs` gains `pub mod modq; pub mod msauth; pub mod dilithium_host;`.
3. Mirror into the excluded files: `asm.rs` `ops::call_modq`, `guests.rs` `compiled::{dilithium_verify, msauth}`, the two bins + `.sha256`.
4. Dev-deps `crystals-dilithium = "=2.0.0"`, `sha3 = "=0.10.9"` for `tests/{dilithium,msauth,modq_reference}.rs` (or exclude them).
5. Exclude `tests/modq_cheating.rs`; assert the vendored `tests/cheating.rs` compiles without any feature.
6. Assert domain tags `AUTH == 65` equals the local auth domain, and 66–69 are distinct from hidden (64) and perps (21–23).
7. Admission pins exact tier 18, heights 12/12/14/0/16/7/20, `pv::GAS == 436 159`, never proof length; off-by-one refused.
8. `_with_modq` everywhere on the multisig path, including the canonicality count via `chips_with_modq`.
9. `modq_log_height == 0` pinned in every other program record and on the aggregate/tree paths.
10. Measure the msauth Production size before the cut.
11. Re-pin `inner_vk_digest` 1b0c4b00…, `verify_rv32.digest` 79ebe02b…, `aggregate_program_digest` 8bc2cecb…, drop every phase-4 and pre-phase-4 digest/key, and mirror `MODQ_GAS = 168` in the fee schedule.

**Production prove at `M = 3`: pending.** The cause of the roughly 1300 s kill of three attempts on a
48 GB laptop is under investigation; see `docs/04-guests.md`.

**Recursion: re-pinned once, after rVM phase 4 (2026-10-11).** rVM phase 4 (`bba7875`, the Merkle
spans) and `origin/main` (`9a1cba6`) were merged into this branch (merges, never a rebase; `26f547e`,
the scan-compact merge, survives), and the recursion pins were re-recorded once, after both, from
measured runs. Phase 4's rule carries over: opcodes 25 (`SPONGE`) and 27 (`COMPRESS`) read their
fourth word as an absolute address under an unchanged rVM verifier key, so every pre-phase-4 program
digest, aggregate or tree digest and key must be dropped at the cut, with none surviving in its old
meaning (`recursion/docs/09-phase4-spans.md` §5–6). The MODQ cpu column then moved every inner pin
again, so the phase-4 values below are stale too: the fullnode re-vendor greps for both columns.

| pin | before MODQ (phase 4) | after | where |
|---|---|---|---|
| `verify_rv32.digest` (production) | `6a70c377…d344` (`cf5a350a…1788` before phase 4) | `79ebe02b…283b` | `recursion/src/programs/verify_rv32.digest` |
| production `aggregate_program_digest` | `e0eede8b…b6c3` (`dc350ecf…8ba0` before phase 4) | `8bc2cecb…d8c7` | `tests/aggregate.rs` |
| test-shape aggregate digest | `1bcbcec9…1fba` | `e26f37e3…41a0` | `tests/verifier.rs` |
| Off-replay digest | `759b015d…9b4e` | `ac1f08cf…d406` | `tests/verifier.rs` |
| `inner_vk_digest` (test fixture shape) | `346ee184…5fb9` | `1b0c4b00…ddc7` | `tests/aggregate.rs`, `recursion/docs/02-aggregate.md` |
| one production inner verification | 315 952 rows, tier 19 | 315 391, tier 19 | `pins.json`, `tests/exit.rs` |
| test-profile single verification | 104 150 rows, 11 875 permutations | 104 229, 11 894 | `tests/verifier.rs`, `tests/exit.rs` |
| test aggregates N=1/2/3 | 104 477 / 208 571 / 312 665 | 104 556 / 208 729 / 312 902 (tiers 18/18/19) | `pins.json`, `N3_ROWS` |
| production aggregates N=1/2/3 (emulated) | 316 279 / 632 175 / 948 071 | 315 718 / 631 053 / 946 388 (tiers 19/20/20) | `tests/aggregate.rs` |
| reduce rows a proof, test / production | 39 296 / 196 480 | 39 392 / 196 960 (heights and N ceilings unchanged) | `tests/aggregate.rs` |

No recursion tier moved. `LOOP_OVERHEAD` stays 327, and the rVM verifier keys
(`tests/verifier_key.rs`) are unchanged. Production rows fell by 561 even though the opened row is one column wider, and the fall is
accounted for exactly: +178 (phase 5, the new cpu constraints), +60 (phase 6 preamble: one more main and one more permutation column opened at ζ, ζg), −720 (tape reads), −79 (`input_root`'s sponge tail). The −720 is `Builder::hint_array` (`recursion/src/dsl/builder.rs`): one HINTN per full 8-word block but a HINT+STORE pair per tail word. The cpu's extra main and LogUp aux column move two height-18 `row ‖ salt` buffers (words incl. 4 salt): the main group 295 → 296 (tail 7 → 0: HINT −7, STORE −7, HINTN +1 = −13 rows a query) and the permutation group 80 → 82 (tail 0 → 2: +4), net −9 rows × 80 queries (measured with a temporary `eprintln!` in `read_input_openings`, `tests/profile.rs` `where_the_rows_go`, at `bba7875` and at HEAD; every other group is unchanged). The −79 is `input_root`'s padding-free sponge (`dsl/hash.rs`, rate 4): the wider row adds one full SPONGE that replaces LOAD/STORE tail copies, −1 a query. In `tests/profile.rs` it falls in the `(none)` call site (98 609 → 98 127) and in `input_root` (90 329 → 90 250).

**Stale until a RAM window or a 256 GB machine.**

- `tree_test` and `tests/tree-test-genesis.json` were re-recorded in 1ed3d69 (no longer stale).
- `pins.json` `tree_measure` (the production leaf, at 632 175 rows, is now 631 053 by the N=2
  emulation).
- `tree_measure.rs`'s `production_leaf_l2` and `production_rv32r_over_the_leaf_proves`, which need
  the 256 GB droplet.

## ZKVM-111: the quotient layout and rate 1/4 on the RV32 machine (opt-in, `next-set`)

The RV32 machine runs at blowup 8 with Plonky3's one-matrix-per-quotient-chunk layout; the rVM
moved to one matrix per instance and to blowup 4. Both moves are now available here **as
opt-in entry points behind the cargo feature `next-set`**, measured, and not live:
`machine::QUOTIENT_LAYOUT` is `PerChunk`, `FriProfile::{Test, Production}` are blowup 8, and
`Machine::{prove, verify}` are what they were. `tests/verifier_key.rs`, `key_blob.rs`,
`proof_binding.rs` and `zk.rs` pass unchanged.

What the feature adds:

- `Machine::prove_traces_with_layout` / `verify_with_layout` (the vendored `p3-batch-stark`
  fork's `_with_layout` entry points). `verify` is now `verify_under(.., QUOTIENT_LAYOUT)`,
  which for `PerChunk` is the fork's `verify_batch`.
- `FriProfile::Quarter` (blowup 4, 92 queries, 24 grinding bits — the rVM's numbers) and
  `FriProfile::QuarterTest` (blowup 4, 16 queries, 4 bits). `FriProfile::log_blowup()` is 3 for
  the two live profiles, whose postcard encodings (0 and 1) are pinned.

**The degree-8 tables do not block blowup 4.** The issue (and `tests/tables.rs`'s comment)
reasoned that the cpu and alu tables' degree 8 forces 8 quotient chunks and therefore blowup 8.
The rVM already proves degree-8 chips at blowup 4 — the PCS re-extrapolates onto the larger
quotient domain — and this machine does too: `tests/quotient_layout.rs::
the_machine_proves_and_verifies_at_rate_one_quarter` proves and verifies all ten
`guests::all()` programs at tier 10 under `QuarterTest`, both layouts, with no AIR change, and a
forged output is refused. The per-table degrees, measured: program 2, **cpu 8**, memory 4,
**alu 8**, range 2, nibble 2, poseidon2 4, input 2, keccak 3, sha256 4, modq 4, public 2. So
lowering cpu and alu to degree ≤ 5 is not a precondition of rate 1/4; it is the lever for the
*quotient transient* (the matrix of the old LDE size held while the quotient is computed),
which is why the layout saves 30 % at blowup 8 and only 20 % at blowup 4 below.

**Measured** (2026-11-18, the 48 GB development machine, single-threaded, one run each on a
shared box so the times are indicative; `fib(10)` at a forced tier — the heap is set by the
table heights, not by the program; peak live heap from a counting allocator over the prove
only; `tests/quotient_layout_heap.rs`):

| tier | profile | layout | peak live heap | prove | proof bytes |
|---|---|---|---|---|---|
| 12 | Production (1/8, 80 q) | PerChunk (live) | 1.435 GB | 26.4 s | 1 426 026 |
| 12 | Production | PerInstance | 1.008 GB | 19.7 s | 1 117 300 |
| 12 | Quarter (1/4, 92 q) | PerInstance | 0.593 GB | 14.6 s | 1 238 848 |
| 14 | Production | PerChunk (live) | 5.692 GB | 112.0 s | 1 478 443 |
| 14 | Production | PerInstance | 3.995 GB | 92.4 s | 1 166 645 |
| 14 | Quarter | PerChunk | 2.943 GB | 66.4 s | 1 661 886 |
| 14 | Quarter | PerInstance | 2.362 GB | 71.6 s | 1 296 736 |
| 16 | Production | PerInstance | 15.946 GB | 352.4 s | 1 233 939 |
| 16 | Quarter | PerInstance | 9.434 GB | 197.3 s | 1 364 035 |

At tier 14 the layout alone is −29.8 % heap and −21.1 % proof bytes; rate 1/4 with the layout
is −58.5 % heap and −12.3 % proof bytes against today. Tier 16 under today's configuration
(Production, PerChunk) was not run: tier 12 → 14 scales ×3.97, which puts it near 22.6 GB,
past this session's allowance.

**Tier 18 was not run** — the issue's acceptance run. The heap scales ×3.96 to ×3.99 per two
tiers in every measured pair, so the projections are: today's configuration about 91 GB,
PerInstance at rate 1/8 about 64 GB, **`Quarter` + PerInstance about 38 GB**. That is under
48 GB but not by a margin that makes "completes on the 48 GB machine" a safe claim: it is a
projection of live heap, and the ERC-20 guest also carries a keccak table that `fib` does not.
The run, from a plain terminal:

```sh
cd research && caffeinate -is cargo test --release --test quotient_layout_heap \
  quarter_tier18_per_instance -- --ignored --nocapture --exact
```

**Security, as far as it was checked.** `Quarter`'s numbers are the rVM's, for which
`recursion/docs/07-rvm-rate-quarter.md` derives 86.38 proven bits against 86.41 (the
low-degree-test term, unique decoding) and checks them with `p3-security` over the rVM's chip
shapes. That computation has **not** been repeated for this machine's chips, so "not lower than
today's by more than 0.03" is the rVM's result carried over, not a result here. 92 queries is
inside the private-data floor (`2^7 ≥ queries + 2`), asserted at compile time under the
feature.

Left for the cut:

1. Flip `QUOTIENT_LAYOUT` and the two live profiles' blowup, queries and grinding; bump
   `CONSTRAINT_SET`; re-pin every key (the preprocessed LDE is half as tall).
2. `p3-security` over this machine's shapes at `Quarter`, as `recursion/tests/security.rs`
   does for the rVM.
3. `../recursion`: `InnerShape::quotient_layout()` answers `PerChunk` and the verifier program
   replays an 80-query, blowup-8 inner proof; both follow, and every aggregate digest moves.
4. The GPU / reference backends (`prove_on`) take `prove_batch`, not `_with_layout`.
5. The quotient transient: an auxiliary column for the alu's `div` sign fix and a narrower
   lookup packing on the cpu would bring both to degree ≤ 5 and 4 quotient chunks. Not priced
   here beyond the 30 % against 20 % observation above.
6. Run tier 18 (ERC-20), tier 20 (SPL transfer) and the msauth M = 3 prove, and record them.

## Constraint set 10: a digest-prefix row costs a permutation

ZKV-5 (fullnode audit v6, `randprotocol/zkp-circuits#2`). The digest-prefix rows (`IS_DIGEST`
`⌈words/4⌉`, `IS_INDIGEST` the salt row plus `⌈n_in/4⌉`, `IS_PUBDIGEST` `max(1, ⌈n_pub/4⌉)`) each make
one `POSEIDON2` call and count against the poseidon2 table, but were charged 1 gas against an absorb
row's 3. Pricing accuracy only: the under-count was once per proof, `2·P` gas for `P` prefix rows. A
chain-side surcharge cannot replace this, because `n_in` is private (the COV-2/INT-6 floor).

**What moved.**

- `gas::gas_of` charges `POSEIDON2_ABSORB_GAS` per prefix row; the cpu AIR's first row asserts
  `GAS = 3`, `w_next`'s absorb term reads `n(IS_HASH) + n(IS_DIGEST) + n(IS_INDIGEST) +
  n(IS_PUBDIGEST)` (still degree 2, the four selectors are pairwise exclusive), and `cpu_trace`'s
  prefix loop follows.
- `gas_max` is unchanged. A run's gas is `(P + C) + 2·(P + A) + …` for `C` cycles and `A` absorb rows:
  `P + C ≤ 2^t − 1` by the cpu height and `P + A ≤ 2^(t−3)` by the poseidon2 slots, so the terms
  `2^t − 1` and `2^(t−2)` still cover it, and now exactly: `tests/gas.rs` proves a run at the ceiling
  with zero slack.

**What did not move: the RV32 verifier keys.** `CommonData` is the preprocessed commitment and the
packed lookups, and this change adds no column, no lookup and no preprocessed table, so every
`tests/verifier_key.rs` digest stands. What separates cs9 from cs10 is the constraint itself (a
trace at the cs9 weights no longer verifies, `tests/gas.rs`) and the `constraint_set` stamp in a `VerifierKeyBlob`, so any pinned SHA-256 of a blob does move.

**What did move, downstream.** The rVM programs compile the cpu AIR's constraints
(`recursion/src/programs/constraints.rs`), so the `verify_rv32`/`rv32n` program digests and the rVM
keys committing those programs move, by +7 cpu rows per inner proof and no tier; `rv32t` and `rv32r`
read no inner constraint and do not. `recursion/docs/10-phase5-n2-tier19.md` has the table.

**Re-vendor checklist: the node's constraint-set guard will not go red by itself.** The fullnode's
`BUILD_CONSTRAINT_SET: u8 = 9` (`crates/randprotocol-node/src/node.rs`) is a separate constant, read
only by a test's assert, so the re-vendor leaves it at 9 with every test green. `check_build_runs_genesis`
keys on `hc_bundle` and `hc_auth`, and neither moves in constraint set 10: no guest changed. So a cs10
binary installed on a chain-21 host passes that check, refuses the chain's own history at its startup
replay, and a `verify --repair` truncates it. The cut that carries cs10 must, in the fullnode:

1. bump `BUILD_CONSTRAINT_SET` to 10 and its assert in `this_build_refuses_chains_18_to_20`, and
   preferably derive the constant from the vendored `randprotocol_zkvm::machine::CONSTRAINT_SET`
   (`u32` there, `u8` here), so the next set cannot miss it;
2. add chain 21 and any other chain that commits proofs under constraint set 9 to
   `CHAINS_THIS_BUILD_CANNOT_RUN` by genesis hash (the array's length with it), with a new
   `CONSTRAINT_SET_9_REASON` naming the release to run instead and a test pinning each row;
3. update the `CONSTRAINT_SET_*_REASON` and `SPLIT_AUTH_REASON` strings, which all say "this build is
   constraint set 9".

A live cs9 chain moved to cs10 is a new genesis, as every set before it.

**Re-vendor note: `evm-core` gained `MCOPY`, `TLOAD`/`TSTORE` and `CLZ`** (branch
`feat/evm-cancun-osaka`; no constraint-set change). The interpreter used to trap (`Halt::Trap`, status
2) on `0x5e`, `0x5c`, `0x5d` and `0x1e`; it now executes them (EIP-5656, EIP-1153 over a 16-key
transient table, EIP-7939). That is a semantic change for any chain that runs `evm.bin`: a call whose
bytecode reaches one of them proved status 2 before and proves its real outcome now. The committed
interpreter image moved with it — `guests-compiled/bin/evm.bin` hc `7e1aea2b…2b854c08` →
`31e682ec…b6c289c3`, program id `99694342…2c44762b` → `47df46b2…d6c9f3978c`, 18 009 → 19 637 program
words, the ERC-20 `transfer` 121 638 → 124 606 executed cycles (still tier 18). The fullnode vendors
`evm-core` (`deploy/sync-zkvm.sh`'s `for CRATE in evm-core sbpf-core`), so its re-vendor must move
every pin of the `evm` guest's hc or program id it holds, and a chain that admits `evm.bin` by hc
admits the new one only at a cut. Translated contracts (`evm2rv`) are unaffected unless their
bytecode contains the new opcodes: the ERC-20's stage-one and stage-two hcs are unchanged.

## Constraint set 11: gas weights that are the committed-cell count

ZKVM-202 (fullnode #167; the owner's ruling of November 2026: adopt the counted weights at the next
constraint set, Keccak and SHA-256 lowered with the rest). `docs/07-gas.md` has the method, the
table, the soundness argument for the per-op `MODQ` price and the fee note for governance.

**What moved.**

| | sets ≤ 10 | set 11 |
|---|---:|---:|
| `POSEIDON2_ABSORB_GAS` (absorb row, digest-prefix row, the first row's `GAS`) | 3 | 4 |
| `KECCAK_GAS` | 192 | 134 |
| `SHA256_GAS` | 64 | 49 |
| `MODQ` `NTT` / `INTT` / `DOT4` / `MSUB4` | 168 flat (`MODQ_GAS`) | 193 / 193 / 264 / 304 |
| `gas_max` at tier `t`, no hash table | `2^t − 1 + 2^(t−2)` | `2^t − 1 + 3·2^(t−3)` |
| ceiling per keccak / sha256 / modq block | 191 / 63 / 167 | 133 / 48 / 303 |
| cpu `col::WIDTH` | 283 | 284 (`MODQ_W`) |
| `MODQ` bus message | `(clk, base, a1)` | `(clk, base, a1, weight − 1)` |
| `msauth` pinned gas word, `gas_max_with_modq(18, 14, 0, 16)` | 436 159 | 447 935 |
| `msauth` metered gas, `M` = 1 / 2 / 3 | 111 217 / 216 576 / 321 575 | 108 056 / 208 621 / 308 826 |

- `gas.rs`: `MODQ_GAS` is gone; `MODQ_NTT_GAS`, `MODQ_INTT_GAS`, `MODQ_DOT4_GAS`, `MODQ_MSUB4_GAS`,
  `MODQ_MAX_GAS`, `modq_gas(op)` and `modq_op(a1)` replace it. `row_gas` prices a `MODQ` row by
  `a1`'s low two bits; `gas_max_with_modq` allows every modq block the heaviest op.
- `tables/cpu.rs`: one appended column, `MODQ_W` (not a selector: `(1 − SYS_MODQ)·MODQ_W = 0`);
  `w_next`'s modq term is `n(MODQ_W)` (degree 2 as before); the `MODQ` lookup carries it as a
  fourth field. `tables/modq.rs`: the table entry's fourth field,
  `192·IS_NTT + 192·IS_INTT + 263·IS_DOT + 303·IS_MSUB`. No modq column, no new bus, no new range
  check.
- `MSUB4` is 304, not the 305 proposed on set 10's count: `MODQ_W` widened the cpu table, the slot
  went from 680 to 681 cells, and the weights were taken from the count after the change.
- `msauth`: tier 18 and the pinned heights (program 12, input 12, keccak 14, sha256 0, modq 16,
  public 7, memory 20) are unchanged — a weight moves no row. Only the gas word and the metered
  gas moved.

**What moved with it: every RV32 verifier key.** The appended cpu column and the fourth `MODQ`
field change every shape's packed lookups, so every `common` digest of `tests/verifier_key.rs`
moved, the modq-free shapes too (the cpu's `MODQ` lookup is declared in every batch); no
`commitment` half moved (no preprocessed column changed). Every exported `VerifierKeyBlob` is
refused by a set-11 machine on its `constraint_set` stamp, the tier-18 `msauth` key the fullnode
ships included: regenerate it.

**The re-vendor into the fullnode** (`deploy/sync-zkvm.sh`), beyond the wholesale rsync:

1. Every caller of `gas::MODQ_GAS` stops compiling (deliberately): the fee schedule's mirror of the
   weights becomes the seven constants above, per op for `MODQ`. A fee table keyed on the syscall
   number alone cannot express set 11: `MODQ`'s price needs `a1 & 3`.
2. `msauth` admission pins `pv::GAS == 447 935` (was 436 159), same tier and heights; the
   off-by-one refusals move with it. Any admission rule that pins another guest's header-ceiling
   gas word moves by the table above (`bundle`, `auth`: `gas_max` at their tier and heights).
3. `BUILD_CONSTRAINT_SET` to 11, and the set-10 chains (and any still listed for set 9) into
   `CHAINS_THIS_BUILD_CANNOT_RUN` by genesis hash with a `CONSTRAINT_SET_10_REASON` — the
   constraint-set-10 checklist above, one set on. `check_build_runs_genesis` keys on guest hcs, and
   no guest image changed in set 11 (`guests-compiled/bin/*` are byte-identical; a guest does not
   embed a weight), so that check will not catch a set-10 database under a set-11 binary.
4. Re-export and re-pin every shipped verifier key blob and every pinned key digest
   (`inner_vk_digest`, the `msauth` tier-18 blob's SHA-256).
5. Re-pin the rVM side from `recursion/` (below): `verify_rv32.digest`, `aggregate_program_digest`,
   the rVM verifier keys that commit those programs, and the genesis `aggregation_tree` values.
6. `tests/modq.rs` is vendored and now asserts `cpu::col::WIDTH == 284` and the per-op weights;
   `tests/common/modq_run.rs`'s asker has a fifth column.

A live set-10 chain moved to set 11 is a new genesis, as every set before it.

**The fee change, for governance** (`docs/07-gas.md`, "What the re-weighting does to a fee"). At an
unchanged price per gas: a plain cycle is unchanged; a `KECCAK` permutation −30 %, a `SHA256`
compression −23 %; `MODQ` `NTT`/`INTT` +15 %, `DOT4` +57 %, `MSUB4` +81 %; a Poseidon2 absorb row
and every digest-prefix row +33 % (so every proof's floor rises by its prefix row count). `msauth`
meters 2.8–4.0 % less (108 056 / 208 621 / 308 826 at `M` = 1 / 2 / 3), but it proves with
`gas_limit = None` and a fee charged on its public gas word, the header ceiling, rises 2.7 %
(436 159 → 447 935). Whether the price per gas, the gas tiers or a ceiling-keyed fee should move
to offset any of this is a governance decision and is not made here.

**What moved downstream: the rVM programs, and this time the inner shape.** The rVM programs
compile the cpu AIR's constraints and open its rows, so the wider cpu and the new terms move the
`verify_rv32` / `rv32n` program digests, the inner key digest and the row counts: one production
inner verification is 236 021 rows (235 425 in set 10), N = 1 / 2 / 3 production aggregates
236 347 / 472 311 / 708 275 (tiers 18 / 19 / 20, unchanged), the reduce heights and the N ≤ 5
ceiling unchanged. `rv32t` and `rv32r` read no inner constraint and do not move, but the leaf
program did, so every rVM proof and key over it is stale.
`recursion/docs/10-phase5-n2-tier19.md`, "Constraint set 11", has the table.

**Re-pinned on the laptop** (emulation and tier ≤ 14 key generation only):

- `research/tests/verifier_key.rs`: the five `common` digests (Test and Production share them);
- `research/tests/gas.rs`, `gas_cells.rs`, `heights_bounds.rs`, `cheating.rs`, `modq.rs`: the
  weights, ceilings, the 681-cell slot, per-op cells, `msauth`'s gas and gas word;
- `recursion/src/programs/verify_rv32.digest`; `recursion/tests/pins.json` (the production
  single-proof block, the three test aggregates, `phase3_attribution`'s REG accesses, reloads and
  spills, `tree_measure.leaf_cpu_rows_emulated`); the production and test aggregate digests, the
  Off replay, the test `inner_vk_digest`, the reduce rows (`tests/aggregate.rs`, `verifier.rs`,
  `exit.rs`); `recursion/docs/02-aggregate.md`'s test vectors.

**Pending operator runs for constraint set 11.** Not run from the agent's session (8 GB limit);
the pins they feed are left at their old values, nothing is guessed:

1. *The `msauth` Production prove* at `M = 3`, tier 18 (≈ 76 GB footprint), which also yields the
   proof size the fullnode pins: `MSAUTH_PROVE_M=3 /usr/bin/time -l cargo test --release --test
   msauth msauth_proves_at_m_production -- --ignored --nocapture`, once more with
   `MSAUTH_PROVE_M=1`, then `msauth_proof_headers_match_across_m -- --ignored`. Result: the header
   line it prints (tier 18, heights 12/12/14/0/16/7/20, gas `447935`) goes to
   `docs/04-guests.md`, "Production prove", and to the fullnode's admission pin. The gas word
   itself is not pending: it is `gas_max_with_modq(18, 14, 0, 16)`, asserted by
   `tests/gas_cells.rs`.
2. *The tier-18 `msauth` verifier key blob* the fullnode ships (stamped `constraint_set = 11`
   now; a set-10 blob is refused on install): `cargo +1.98.1 test --release --test key_blob
   export_the_production_msauth_key -- --ignored --nocapture` (≈ 4 GB, ≈ 80 s; the test's own note
   says to run it outside the agent harness). It writes `target/msauth-tier18-production.vkblob`
   and prints `KEY-BLOB: … sha256=…`; the blob and that digest go to the fullnode's shipped key
   and its pin. No copy of the blob or its digest lives in this repository.
3. *`research` tests `bundle`, `viewing`, `e2e`* (tier 14 and 16 proofs; outside CI's research
   job for memory): `cargo test --release --test bundle --test viewing --test e2e`. They pin
   proof-size bands, not weights; a failure there would be a size band to re-measure.
4. *The rVM side*: the test tree's fixtures (≈ 34 GB) and the `tree_test` / `tree-test-genesis.json`
   pins that follow from them, the Test twins, the production exit and aggregates and the
   production tree — the table in `recursion/docs/10-phase5-n2-tier19.md`, "Pending operator runs
   for constraint set 11", has each command and where its result goes. Until the test-tree
   fixtures are regenerated the fixture-gated tests of `recursion/tests/tree.rs` fail with
   "rvmproof is missing or stale", as after phase 5.
5. *The CUDA backend* (`rand-zkvm-cuda`): mirrors no weight and no cpu width (it takes the trace
   width from the matrix), so nothing to re-pin; its device tests need a GPU host and were not
   run.

**Re-vendor note: the EVM guest's public output binds the call, the log data and the gas**
(ZKVM-103, ZKVM-104; no constraint-set change). The `EVM_OUT` preimage grew from 40 words to 82:
after `logs_hash` it now carries `address`, `caller`, `callvalue`, `keccak256(calldata)`, an
eight-word `context`, `gas_limit` and `gas_used`; `logs_hash` covers each log's
`keccak256(data)` after its topics; and the input vector has eight `context` words between
`gas_limit` and `pre_root`. Every proof of the old image and every digest a consumer computed for
it is void: a node that checks EVM outputs has to compute the 82-word digest
(`rand_zkvm::evm::EvmStatement`, which it should fill from the transaction it authenticated — that
is the authorisation check) and supply a `context`. The committed interpreter image moved —
`guests-compiled/bin/evm.bin` hc `31e682ec…b6c289c3` → `08740025…c4dc0f23`, program id
`47df46b2…d6c9f3978c` → `f056f928…8567ec70`, 19 637 → 20 077 program words, the ERC-20 `transfer`
124 606 → 128 872 executed cycles (still tier 18) — and so did **every** `evm2rv` translation,
which links the same `evm-core` harness and `evm-rt`'s `evm_log` (the ERC-20's two pinned hcs are
in `evm2rv/README.md`). A chain that admits `evm.bin` or a translated contract by hc admits the
new one only at a cut.

## ZKVM-115: a 256-bit modular multiply-add chip (prototype, `next-set`)

Signature and pairing work is out of reach in software: `ecrecover` is 14.5 M cycles against a
2^20 ceiling. The MODQ chip took Dilithium2 verification to 80 572 cycles and is the template.
This section records how far that template carries to 256-bit fields, and the prototype that
was built: `src/tables/mulmod256.rs`, compiled only under the cargo feature `next-set`.

**Status: an AIR proved standalone, not a coprocessor.** One row proves
`r = (a·b + c) mod p` for 256-bit operands and a caller-supplied 256-bit modulus, with the
quotient as a witness. It is proved in a two-table batch with the range table
(`tests/mulmod256.rs`) and attacked there. It has **no syscall, no cpu handshake, no memory
traffic and no gas weight**, `machine::chips` does not include it, and no guest can call it —
so the constraint set, the keys and the proof format are untouched, and the issue's acceptance
line ("ecrecover and Ed25519 verify each fit inside one tier-20 proof") is **not met or
tested**.

**What carries over from MODQ, and what does not.**

- Carries over: a dedicated table off the cpu; one cpu cycle per call; the chip owning its own
  memory traffic; byte limbs checked on the existing `RANGE8` bus (no new range table); a
  canonical-result rule (`D = p − 1 − r`); a forgery suite; one constraint-set bump.
- Does not: the arithmetic. MODQ proves `O + q·K = α·U + β·V` as one field identity because
  `q < 2^23` keeps every term under Goldilocks' `2^64`. A 256-bit product fits no field
  element, so the identity is proved limb by limb with explicit carries (64 limb equations, 63
  two-byte carries). And the block geometry: MODQ's 1 024-row block is a whole NTT; here one
  row is one operation.

**The row** (`tables::mulmod256`'s module comment has the rules): 384 main columns — `A`, `B`,
`C`, `P`, `R`, `D` (32 byte limbs each), `Q` (33), 32 boolean carries of the canonical chain,
63 product carries of two limbs. 130 constraints, every one of degree 3. 351 `RANGE8` lookups
per real row. Measured in the standalone batch: 236 committed LogUp auxiliary columns and 8
quotient chunks, so **620 committed base cells per operation**. For scale, one cpu row is 283
main columns before its own auxiliary columns, and one such operation costs thousands of cycles
in software.

**Tested** (12 tests, release, about 4 s):

- the host arithmetic equals big-integer arithmetic for secp256k1's field and group order,
  ed25519's field and bn254's field, on random and extreme operands;
- honest rows satisfy every constraint; 100 operations prove and verify (Test profile, 0.3 to
  0.5 s, a proof of about 158 kB);
- the forgery suite, each a real proof refused by the verifier, with a control showing the
  harness accepts the honest row: a wrong result; a **non-canonical result** (`r + p` with
  `q − 1` — a true integer identity with every limb a byte, refused only by the canonical
  chain); a wrong quotient; **out-of-range limbs** in each of `a`, `b`, `c`, `q` (the integer
  re-encoded with one limb ± 256: every arithmetic constraint still holds and only the range
  lookup refuses it) and in `p`, `r`; an out-of-range carry limb; another operation's result.

**Limits of the row as built.** The quotient has 33 limbs, so the modulus must be at least
`2^248` or the operands reduced; all four target moduli are above `2^253`, and a smaller
modulus has no row rather than a wrong one. `a`, `b`, `c` are not required to be below `p`.

**An estimate, not a measurement.** `ecrecover` is one square root, one double-scalar
multiplication and two inversions: on the order of 5 000 field multiplications and as many
additions and subtractions, each one chip row (an addition is `a·1 + c`). At roughly 20 cycles
of guest glue per call that is some 10 000 rows and 200 000 cycles — tier 18 — against
14 510 525 today. No guest was written, so this is arithmetic on textbook operation counts; the
real count needs the guest.

**Left, in order.**

1. Integration, MODQ's way: a syscall number and `SYS_MULMOD` cpu row; a `(clk, ptr)` handshake
   bus; the chip's `MEMORY` sends (32 words read, 8 written per call — each word is a linear
   form of four limbs, so no new columns, but 40 sends a row where MODQ has five); a declared
   table height in the proof header and the key tuple; `Tier::max_mulmod_log_height`.
2. A gas weight from the measured cells per call (620 against the cpu's row), by the method of
   the MODQ gas issue.
3. The forgery suite again on the integrated chip, behind `cheating`: the handshake, the memory
   traffic, a real block the cpu never asked for, padding.
4. A guest: field arithmetic for secp256k1 over the syscall, `ecrecover` against known
   vectors, and the measured cycle count. Then ed25519 — `verify_strict`-equivalent, against
   dalek's vectors — and the EVM precompiles 1, 5, 6, 7 and the Solana syscalls.
5. Only then decide on curve-level syscalls (point add / double), from the measured counts.
6. Narrower rows: 16-bit limbs with a 2^16-row range table would cut the columns and lookups
   by about half; not priced.
7. Pairing (a 1 768× gap) stays out of scope.

**Re-vendor note: the EVM guest has two storage layouts and two images** (ZKVM-105; no
constraint-set change). `evm-core`'s storage tree is depth 64 by default (layout 2: the leaf
position is the top 64 bits of `keccak256(slot)`, a witness is 528 words, `MAX_WITNESSES` is 32)
and depth 32 under its new `storage-v1` feature (layout 1); the `EVM_OUT` preimage is 83 words,
the layout first. `guests-compiled/bin/evm.bin` is now the layout-2 image and a new
`guests-compiled/bin/evm-v1.bin` the layout-1 one (hcs and program ids in the PR and in
`rand-guest info`); `rand_zkvm::guests::compiled::evm_images()` lists both. A storage root built
under the depth-32 tree is **not** a root under layout 2: a contract either stays on `evm-v1.bin`
or is re-rooted (`evm::SparseTree::migrate`) at a cut. The fullnode needs, and does not have:
admission of more than one `hc` for the EVM guest, a layout field in a contract's record, and
`EvmStatement.layout` set from it. `deploy/sync-zkvm.sh` rsyncs `research/src`, which now
`include_bytes!`s both images.

## Relationship to `../../fullnode`

`fullnode/` does not exist yet; this crate is its seed, not its dependency
today. The intended shape, once it does: the node embeds
`rand_zkvm::machine::Machine::verify` as consensus code — every full node
runs the same verifier against the same recomputed `CommonData`, exactly as
it would run any other deterministic state-transition check. Provers (the
role that runs `Machine::prove`/`prove_traces`) are a separate, off-consensus
concern — anyone with the witness can produce a proof, and the node never
needs to. That split is why `verify`'s cost (a full preprocessed-commitment
recomputation, `docs/03-privacy.md`) matters more than `prove`'s: it runs on
every validating node, on every transaction, while proving runs once, off
the consensus path.

**Vendoring, as of constraint set 6.** A guest whose binding depends on the
public segment — the sBPF one does — needs the node to call
`Machine::verify_public(hc, public_words, proof)` rather than plain `verify`,
and to carry the segment's words alongside the proof so it can. The sync
script `deploy/sync-zkvm.sh` makes exactly two patches, and constraint set 6
breaks both: the `log_ext_degrees_pub` wrapper is anchored on
`Machine::verifier_key`'s **exact signature line**, which gained a sixth
parameter (`public_log_height`) — the script `assert`s that anchor and aborts
the sync rather than mispatching silently, so this one fails loudly — and the
`crate::notes::domain::(HC|IN)` inlining, which exists because `notes.rs` is
not vendored and which this set gives a **third** case to cover,
`crate::notes::domain::PUB` (= 15) in `src/hash.rs` and `src/tables/cpu.rs`.
Nothing asserts on that one, so an un-extended script produces a node that
simply does not compile. `pv::NUM` needs no anchor at all — it is a constant
in a file the script rsyncs wholesale — which is worth saying because earlier
drafts of these notes claimed the script tracked it. The recursion VM (M5) is
unaffected — its own spec states the rVM has no salted input commitment and
lists this segment as out of its scope.
