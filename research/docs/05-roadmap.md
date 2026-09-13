# Roadmap

## Milestones

| # | Scope | Exit criterion | Status |
|---|---|---|---|
| M1 | Tables (program, cpu, memory, alu, byte), ISA row M1, syscalls 0–1, ZK on, tier padding, assembler, emulator, tests, guidance README + `docs/01–05` | `fib`, `memcpy`, `bubble_sort`, `alu_mix` (and `balance_check`) prove and verify with ZK at their tiers; all cheating tests reject | **done** — 44 tests pass, the narrated demo runs clean |
| M1.5 | Viewing keys: a one-in-one-out shielded transfer guest with in-circuit commitments and nullifier (software `Arx8` hash), note envelopes (ML-KEM-768 + ChaCha20-Poly1305), party- and transaction-scoped disclosure, row verification against the chain, a simulated ledger (`docs/06-viewing-keys.md`) | a transfer proves at tier 12 and a ledger accepts it; each disclosure scope opens exactly its own rows; every row verifies; a viewing key cannot spend | **done** — 6 tests, Part 9 of the demo |
| M2 | Sub-word loads/stores, the M extension, a flat-binary loader, `READ_INPUT` bound to something | a guest compiled with an external RISC-V toolchain runs and proves | **done** (M2.1–M2.6, this milestone's six-task implementation plan): verifier key cache — done; FRI retuned to a 100-bit conjectured target — done, and **reverted 2026-09-12 on the zk audit** (deviation 6 below: the retune kept the conjectured bound but gave up the proven proximity-gaps floor; `Production` is back to the whitepaper's 80/8/20); the 2^16-row byte table split into 256-row range and nibble tables — done; the ALU's RANGE8 limb checks collapsed to op-gated (`g_ab`/`g_c`) — done; sub-word loads/stores `LB LH LBU LHU SB SH` as a read-modify-write over word-addressed memory — done; the RV32M extension (`MUL MULH MULHU MULHSU DIV DIVU REM REMU`) as exact integer identities — done; 81 tests total. The flat-binary loader and a firmer `READ_INPUT` binding, carried forward as open items, were closed in M4.1 (`docs/superpowers/plans/2026-09-11-zkvm-m4-1.md`) |
| M3 | Poseidon2 chip, `POSEIDON2` syscall plus `NOTE_COMMIT`/`NULLIFY`/`MERKLE_VERIFY` guest routines, program digest moved in-circuit as a public value; `Arx8` retired and `cm_in` moved from public output to Merkle witness | the zkp6/zkp4 transfer relation re-expressed as a guest proves under `R_exec`, with membership in-circuit | **done** — M3.1 (Poseidon2 chip, one row per round, `POSEIDON2` bus), M3.2 (`POSEIDON2` syscall = 3, absorb/write-back cpu hash rows), M3.3 (`NOTE_COMMIT`/`NULLIFY`/`MERKLE_VERIFY` guest routines, the transfer guest rewritten around in-circuit membership, the ledger's commitment tree, `Arx8` retired) and M3.4 (the program table as a witness trace with an in-circuit decoder, `hc` as an in-circuit digest pinned to `pv::HC0..HC7`, `Machine::verify(hc, proof)`, the verifier key collapsed to one per (tier, declared program height) — deviation 1 below closed) all done — 117 tests, `docs/06-viewing-keys.md` |
| M4 | EVM and sBPF guest interpreters, Keccak/SHA coprocessors (`docs/04-guests.md`) | an ERC-20 `transfer` and an SPL `Transfer` each prove under `R_exec` | in progress — M4.1 (compiled guests, flat-binary loader, `READ_INPUT` bound to `H_IN`) **done**; M4.2 (the Keccak-f\[1600\] chip, `KECCAK` syscall = 4, proof-declared keccak and memory heights, the keccak table optional per proof, the compiled `keccak256` guest) **done** — the suite stood at 223 tests then (222 pass, 1 ignored), M4.2 adding 38 of them (`tests/keccak.rs` (12, new), `tests/cheating.rs` (+15), `tests/e2e.rs` (+6), `tests/tables.rs` (+5)) and the 2026-09-12 audit port a further 18 (`tests/cheating.rs` (+11), `tests/asm.rs` (+5), `tests/e2e.rs` (+1), `tests/emulator.rs` (+1)); M4.3 (EVM interpreter) not started; M4.4 **in progress** — the SHA-256 chip and `SHA256` syscall = 5 are done (`tables::sha256`, `guests::sha256_demo`, the chip optional per proof and the verifier key a 5-tuple; `docs/superpowers/plans/2026-09-12-zkvm-m4-4.md` Tasks 1–4), `sbpf-core` (the SBPF v1 ISA, memory regions, interpreter, syscalls, ELF loader and ABI, differentially tested against `solana-sbpf` 0.11.1) is done (Task 5), and the compiled `sbpf` guest and the SPL `Transfer` exit test are not. The suite is 304 tests now (301 pass, 3 ignored), M4.4's chip tasks adding 32 of them (`tests/sha256.rs` (14, new), `tests/cheating.rs` (+11), `tests/e2e.rs` (+4), `tests/emulator.rs` (+2), `tests/tables.rs` (+1)) and Task 5 a further 49 (`tests/sbpf_interp.rs` (20, new), `tests/sbpf_abi.rs` (13, new), `tests/sbpf_elf.rs` (10, new, one `#[ignore]`d until the SPL Token ELF lands), `tests/sbpf_isa.rs` (6, new)) |
| Phase Z | Fully shielded pool, zkVM side (`docs/superpowers/specs/2026-09-11-shielded-pool-design.md` §12): looped `MERKLE_VERIFY`, `u64` amounts, the 2-in-2-out `bundle` guest with dummy inputs and `u64` fee/burn conservation, ledger admission and viewing over bundles | `bundle` proves and verifies at a measured tier; every §13 cheating scenario is rejected (structurally or by the STARK); a party's or a transaction's viewing key opens exactly its bundle rows | **done** — the suite stood at 167 tests (166 pass, 1 pre-existing ignored) when phase Z landed; M4.2's 38 took it to 205, the 2026-09-12 audit port's further 18 to 223, and M4.4's chip tasks' 32 to 255. Phase Z added 30 of them across Tasks 1–4, 28 in `tests/bundle.rs`, and the 256-bit-`SpendKey` follow-up one more in `tests/viewing.rs` (`docs/06-viewing-keys.md`'s "The `bundle` relation" and "Ledger admission for bundles") |

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

## Known deviations from the whitepaper

These are the design spec's own §12 list, restated with their current
status, plus one deviation introduced during implementation and since
reverted (6), and one refinement that is not a deviation from the whitepaper
but is worth flagging alongside them (7).

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
   section for exactly what changed and what didn't.
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
     instead of nine. The machine-shape consequences are all handled: the keccak
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
     batch carries eight, nine or ten instances and the verifier key's cache key
     grows to `(tier, program, input, keccak, sha256)` — an arity change the
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

7. **Selector refinement (not a deviation, a design choice).** The design
   spec described one flag per mnemonic; the implementation pre-decodes
   23 semantic selector fields instead (`docs/01-isa.md`; M2.5 grew this
   from 18 to 23 by replacing the single `is_load`/`is_store` booleans with
   a one-hot per load/store width plus a `signed` flag). Same trust model
   — the CPU still never decodes a bit — fewer columns than one-per-
   mnemonic, and constraints that read as "if `is_lb+is_lh+is_lw` then …"
   rather than sums over every individual instruction's own flag.

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
