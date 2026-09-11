# Roadmap

## Milestones

| # | Scope | Exit criterion | Status |
|---|---|---|---|
| M1 | Tables (program, cpu, memory, alu, byte), ISA row M1, syscalls 0–1, ZK on, tier padding, assembler, emulator, tests, guidance README + `docs/01–05` | `fib`, `memcpy`, `bubble_sort`, `alu_mix` (and `balance_check`) prove and verify with ZK at their tiers; all cheating tests reject | **done** — 44 tests pass, the narrated demo runs clean |
| M1.5 | Viewing keys: a one-in-one-out shielded transfer guest with in-circuit commitments and nullifier (software `Arx8` hash), note envelopes (ML-KEM-768 + ChaCha20-Poly1305), party- and transaction-scoped disclosure, row verification against the chain, a simulated ledger (`docs/06-viewing-keys.md`) | a transfer proves at tier 12 and a ledger accepts it; each disclosure scope opens exactly its own rows; every row verifies; a viewing key cannot spend | **done** — 6 tests, Part 9 of the demo |
| M2 | Sub-word loads/stores, the M extension, a flat-binary loader, `READ_INPUT` bound to something | a guest compiled with an external RISC-V toolchain runs and proves | **done** (M2.1–M2.6, this milestone's six-task implementation plan): verifier key cache — done; FRI retuned to a 100-bit conjectured target — done; the 2^16-row byte table split into 256-row range and nibble tables — done; the ALU's RANGE8 limb checks collapsed to op-gated (`g_ab`/`g_c`) — done; sub-word loads/stores `LB LH LBU LHU SB SH` as a read-modify-write over word-addressed memory — done; the RV32M extension (`MUL MULH MULHU MULHSU DIV DIVU REM REMU`) as exact integer identities — done; 81 tests total. The flat-binary loader and a firmer `READ_INPUT` binding, carried forward as open items, were closed in M4.1 (`docs/superpowers/plans/2026-09-11-zkvm-m4-1.md`) |
| M3 | Poseidon2 chip, `POSEIDON2` syscall plus `NOTE_COMMIT`/`NULLIFY`/`MERKLE_VERIFY` guest routines, program digest moved in-circuit as a public value; `Arx8` retired and `cm_in` moved from public output to Merkle witness | the zkp6/zkp4 transfer relation re-expressed as a guest proves under `R_exec`, with membership in-circuit | **done** — M3.1 (Poseidon2 chip, one row per round, `POSEIDON2` bus), M3.2 (`POSEIDON2` syscall = 3, absorb/write-back cpu hash rows), M3.3 (`NOTE_COMMIT`/`NULLIFY`/`MERKLE_VERIFY` guest routines, the transfer guest rewritten around in-circuit membership, the ledger's commitment tree, `Arx8` retired) and M3.4 (the program table as a witness trace with an in-circuit decoder, `hc` as an in-circuit digest pinned to `pv::HC0..HC7`, `Machine::verify(hc, proof)`, the verifier key collapsed to one per (tier, declared program height) — deviation 1 below closed) all done — 117 tests, `docs/06-viewing-keys.md` |
| M4 | EVM and sBPF guest interpreters, Keccak/SHA coprocessors (`docs/04-guests.md`) | an ERC-20 `transfer` and an SPL `Transfer` each prove under `R_exec` | not started — M4.1 (compiled guests, flat-binary loader, `READ_INPUT` bound to `H_IN`) — **done**; M4.2–M4.4 (Keccak-f\[1600\] chip, EVM interpreter, sBPF interpreter/SHA-256 chip — `docs/superpowers/specs/2026-09-11-zkvm-m4-design.md`) not started |
| Phase Z | Fully shielded pool, zkVM side (`docs/superpowers/specs/2026-09-11-shielded-pool-design.md` §12): looped `MERKLE_VERIFY`, `u64` amounts, the 2-in-2-out `bundle` guest with dummy inputs and `u64` fee/burn conservation, ledger admission and viewing over bundles | `bundle` proves and verifies at a measured tier; every §13 cheating scenario is rejected (structurally or by the STARK); a party's or a transaction's viewing key opens exactly its bundle rows | **done** — the full suite is 166 tests (165 pass, 1 pre-existing ignored); phase Z added 30 of them across Tasks 1–4, 28 in `tests/bundle.rs` (`docs/06-viewing-keys.md`'s "The `bundle` relation" and "Ledger admission for bundles") |

M1's exit criterion as actually delivered is slightly broader than the
original wording: the demo and test suite exercise four guests, not three,
because `balance_check` is the crate's canonical "confidential computation"
example and earns its place alongside the three original correctness
guests.

M2's exit criterion as actually delivered is narrower than the original
wording: the six-task implementation plan (`docs/`'s M2 design spec) scoped
sub-word memory, the RV32M extension, and three infrastructure sub-tasks
(verifier-key cache, FRI retune, byte-table split) as M2.1–M2.6, and marks
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
status, plus one refinement made during implementation that is not a
deviation from the whitepaper but is worth flagging alongside them.

1. **Closed in M3.4.** `hc` is now an ordinary public value (`pv::HC0..HC7`),
   computed in-circuit by `cpu`'s digest-row prefix over the program table
   (now a witness trace, `docs/02-tables-and-buses.md`'s in-circuit
   decoder) with the Poseidon2 chip, exactly as the whitepaper wants: one
   universal verifier key per (tier, declared program height) (`Machine::verifier_key(tier, program_log_height)`,
   program-independent), `hc` supplied by the caller as an input to
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
6. **Selector refinement (not a deviation, a design choice).** The design
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
