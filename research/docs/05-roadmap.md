# Roadmap

## Milestones

| # | Scope | Exit criterion | Status |
|---|---|---|---|
| M1 | Tables (program, cpu, memory, alu, byte), ISA row M1, syscalls 0–1, ZK on, tier padding, assembler, emulator, tests, guidance README + `docs/01–05` | `fib`, `memcpy`, `bubble_sort`, `alu_mix` (and `balance_check`) prove and verify with ZK at their tiers; all cheating tests reject | **done** — 44 tests pass, the narrated demo runs clean |
| M1.5 | Viewing keys: a one-in-one-out shielded transfer guest with in-circuit commitments and nullifier (software `Arx8` hash), note envelopes (ML-KEM-768 + ChaCha20-Poly1305), party- and transaction-scoped disclosure, row verification against the chain, a simulated ledger (`docs/06-viewing-keys.md`) | a transfer proves at tier 12 and a ledger accepts it; each disclosure scope opens exactly its own rows; every row verifies; a viewing key cannot spend | **done** — 6 tests, Part 9 of the demo |
| M2 | Sub-word loads/stores, the M extension, a flat-binary loader, `READ_INPUT` bound to something | a guest compiled with an external RISC-V toolchain runs and proves | not started (verifier key cache — done; FRI retuned to a 100-bit conjectured target — done; 52 tests total) |
| M3 | Poseidon2 chip, syscalls 10–13 (`POSEIDON2`, `NOTE_COMMIT`, `NULLIFY`, `MERKLE_VERIFY`), program digest moved in-circuit as a public value; `arx::hash` replaced by the chip and `cm_in` moved from public output to Merkle witness | the zkp6/zkp4 transfer relation re-expressed as a guest proves under `R_exec`, with membership in-circuit | not started |
| M4 | EVM and sBPF guest interpreters, Keccak/SHA coprocessors (`docs/04-guests.md`) | an ERC-20 `transfer` and an SPL `Transfer` each prove under `R_exec` | not started |

M1's exit criterion as actually delivered is slightly broader than the
original wording: the demo and test suite exercise four guests, not three,
because `balance_check` is the crate's canonical "confidential computation"
example and earns its place alongside the three original correctness
guests.

## Known deviations from the whitepaper

These are the design spec's own §12 list, restated with their current
status, plus one refinement made during implementation that is not a
deviation from the whitepaper but is worth flagging alongside them.

1. **`hc` is a verifier-side commitment, not yet a public value.** The
   whitepaper wants `hc` as a public input to one universal verifier key.
   Here it is the preprocessed-trace commitment inside a per-program
   `CommonData`; the verifier *code* is universal, but the verifier *key*
   is per-program. Milestone 3 closes this by moving the program into the
   main trace and hashing it in-circuit with the Poseidon2 chip, exposing
   the digest as an ordinary public value.
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
   18 semantic selector fields instead (`docs/01-isa.md`). Same trust
   model — the CPU still never decodes a bit — fewer columns, and
   constraints that read as "if `is_load` then …" rather than sums over
   one-hot mnemonic flags.

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
