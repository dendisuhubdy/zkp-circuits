# Privacy

This is the "what does confidential actually mean here" document: what the
zero-knowledge property covers, what a tier reveals, exactly what a proof
leaks, and where the crate's privacy story stops today.

## Zero knowledge is statistical, not perfect

Proving uses `HidingFriPcs` (`machine.rs::build_config`), which randomises
the low-degree extension of every main trace and the FRI batch polynomial
before committing. `make_config` seeds this from fresh OS entropy for every
proof, so two proofs of the same run are different bytes and both verify —
demonstrated in Part 7 of the demo and in `tests/zk.rs`. This is not perfect
zero knowledge, and the crate does not claim it is: Plonky3 0.7 says so
itself, in `p3-batch-stark-0.7.0/src/prover.rs:469` — `// TODO: This
approach is only statistically ZK.` The gap is a fixed, quantifiable
soundness/privacy tradeoff of the library's blinding technique, not a bug in
this crate; closing it is upstream's work, not this milestone's. Poseidon2's
round constants are likewise derived from a fixed development seed
(`PERM_SEED` in `machine.rs`) rather than the published Goldilocks constants
— a placeholder for the same reason: correct math, wrong constants for
production.

`Machine::new` takes a `FriProfile`: `Production` (27 FRI queries, 20
proof-of-work bits, `max_log_arity: 3` — folding arity 8) or `Test` (16
queries, 4 PoW bits, for a fast `cargo test`). Both use blowup 8 and the same
hiding PCS; only the query count, grinding difficulty, and folding arity
differ. `Production`'s numbers (M2.2) are tuned to the ethSTARK conjectured-
soundness bound `log_blowup·num_queries + query_pow_bits ≥ 100`:
`3·27+20 = 101`; `Test`'s (`3·16+4 = 52`) is not a production target, only
fast enough for the suite. Neither profile is any less zero-knowledge than
the other — only proof size and conjectured soundness change with the query
count.

Before M2.2, `Production` ran 80 queries / 20 PoW bits with `max_log_arity:
1` — conjectured soundness `3·80+20 = 260` bits, far past the 100-bit
target, at a proportional cost in proof size. Measured on `guests::fib` at
tier 10 and tier 12 (`cargo test --release --test e2e
measure_production_profile_at_tier_10_and_12 -- --ignored --nocapture`,
`tests/e2e.rs`). The verify times below are each program's *first* verify on
a fresh `Machine` — an uncached `verifier_key` recomputation, which
dominates them (see "What `verify` actually checks" below); a cached verify
of the same proof runs under 40% of that, per
`tests/e2e.rs::verifier_key_is_cached_after_first_verify`:

| | tier 10 (M2.1 → M2.2 → M2.3) | tier 12 (M2.1 → M2.2 → M2.3) |
| --- | --- | --- |
| proof size | 892 578 → 290 403 → 268 288 bytes | 886 246 → 291 366 → 289 779 bytes |
| prove time | 21.61 s → 20.88 s → 3.11 s | 29.69 s → 29.45 s → 11.44 s |
| verify time (first, uncached) | 2.166 s → 2.148 s → 16.0 ms | 2.178 s → 2.141 s → 18.0 ms |

M2.2 (80 → 27 queries, retuned to the 100-bit conjectured target) cut proof
size to roughly a third at the same conjectured soundness margin; prove and
first-verify times moved by noise, not by the query-count change, because
both were dominated by costs the query count and fold width don't touch:
trace commitment and, for that first verify, the uncached `verifier_key`
recomputation. M2.3 (splitting the 2^16-row byte table into the 256-row
range and nibble tables) is what actually moves those two rows: every
`prove` rebuilds the preprocessed trace's Merkle commitment from scratch,
and every *first* `verify` on a fresh `Machine` does too — shrinking that
commitment by two orders of magnitude cuts prove time by roughly 3-7x and
first-verify time by roughly 100-130x, independent of `FriProfile` (see the
caching paragraph below). Proof size drops a little further too: fewer
preprocessed columns means smaller opening proofs.

## Private inputs are witness, not yet bound to anything

`READ_INPUT idx` (syscall 2) returns whatever word the prover supplies at
that index — a value chosen by the prover, checked by nothing. Nothing ties
two reads of the *same* index together either: the constraint system treats
each `READ_INPUT` row independently, so `READ_INPUT 0` may return one word on
one cycle and a different word on the next and the proof still verifies. The
input array is a per-row witness, not a committed vector; a guest that needs a
stable value must read it once and keep it in a register. Milestone 1's
relation is existential: it proves *"there exist inputs such that running
this program on them produced these outputs,"* full stop for a general
guest — nothing outside the shielded transfer binds a private input to a
note commitment, a nullifier, or a Merkle path against a public state root.
For everything else, "the balance is private" means only that the verifier
never sees the number, not that the number is tied to any real account.

The one exception is the shielded transfer guest, which binds its inputs by
recomputing note commitments and a nullifier in-circuit, proving the spent
commitment's membership in the commitment tree (`POSEIDON2`, `NOTE_COMMIT`,
`NULLIFY`, `MERKLE_VERIFY` — `docs/06-viewing-keys.md`), and publishing a
single digest of the result. That is a per-guest choice, not a machine
property: `READ_INPUT` itself is still unchecked. Since milestone 3.3, the
spent commitment `cm_in` itself is *not* public — only the tree root
(`anchor`) it was proved against is — so the link from a note's creation to
its spend is no longer visible on chain.

## Selective disclosure: viewing keys

A shielded transaction is opaque to the chain and readable by exactly two
kinds of key: a party's viewing key (its whole history, sent and received)
and a per-transaction key (one transaction). Neither can spend. Every row a
key opens carries sender, receiver, amount, asset and time together with the
note opening, so a third party holding the same key checks the row against
the on-chain commitments and nullifiers rather than trusting whoever handed
it over. The construction, the checks, and the honest list of what it does
not yet cover are in `docs/06-viewing-keys.md`.

## `hc` is binding, not hiding — and the program is not secret in M1

`hc` is the preprocessed Merkle root, and `machine.rs::key_config` seeds its
salt from `program_digest`, a deterministic function of the program itself. A
commitment whose randomness is derived from the message it commits to is
**binding but not hiding**: anyone who can guess a candidate program can
recompute `hc` and confirm the guess, and two deployments of the same program
produce the same `hc` and are trivially linkable. The earlier framing — "no
privacy is lost because the program table is public" — was the wrong reason
for the right mechanism.

The right reason is simpler: **program confidentiality is not a milestone-1
property.** `Machine::verify(program, proof)` takes the entire `Program` in
the clear; every verifier holds every instruction word. There is nothing for a
salt to hide, so a deterministic non-hiding digest costs nothing here, and the
determinism buys something real — any verifier can recompute `hc` standalone
without having witnessed the proving session.

That changes in milestone 3, where the code digest moves in-circuit and the
verifier stops holding the program (`docs/05-roadmap.md`). That is the point
at which a *hiding* program commitment — a salt from real entropy, published
alongside the program's ciphertext, or a digest computed under the proof —
becomes both necessary and possible. Until then, treat `hc` as an identifier
for a public program, not as a secret-keeping commitment.

## What `verify` actually checks

`Machine::verify(program, proof)` — the code a node runs — checks, in order:
the proof carries exactly 10 public values; every one of them is a canonical
Goldilocks residue (`< p`, so `out0` and `out0 + p` are not two spellings of
the same proof); `public_values[PC_ENTRY]` equals `program.base_pc`; `public_values[TIER]` equals `proof.tier`; `proof.tier` is
one of the six values in `TIERS` (an attacker-chosen out-of-range tier is
rejected here, before it can be used to compute a table height and panic);
the proof's degree bits match the heights that tier implies for all six
tables; and finally the batch STARK itself, against a verifier key recomputed
from the program. Both `verify` and `code_hash` go through `verifier_key`,
which includes the range and nibble tables' preprocessed commitments (256
rows each, since M2.3 split the 2^16-row byte table in two);
`Machine::verifier_key` caches this per `(program digest, tier)` (64-entry,
FIFO-evicted) — `tests/e2e.rs::verifier_key_is_cached_after_first_verify`
measures the cached hit at under 40% of the first, uncached recomputation
(retuned in M2.3 — the uncached build is now cheap enough that the old 10%
bound no longer held; see the test's own comment).

## Tiers: what padding hides

Trace height never reflects the actual cycle count; it is padded up to the
smallest tier that fits. `cpu` and `alu` pad to `2^ℓ` and `2^(ℓ+1)` rows,
`memory` to `2^(ℓ+2)` (four accesses per cycle, worst case); `program` pads
to the next power of two above the program's own length (minimum 16 rows);
`range` and `nibble` are each always the fixed 256 rows. Padding rows carry
`is_real = 0` and emit nothing on any bus.

| Tier `ℓ` | `cpu` rows | `alu` rows | `memory` rows | max cycles |
|---|---|---|---|---|
| 10 | 1 024 | 2 048 | 4 096 | 1 023 |
| 12 | 4 096 | 8 192 | 16 384 | 4 095 |
| 14 | 16 384 | 32 768 | 65 536 | 16 383 |
| 16 | 65 536 | 131 072 | 262 144 | 65 535 |
| 18 | 262 144 | 524 288 | 1 048 576 | 262 143 |
| 20 | 1 048 576 | 2 097 152 | 4 194 304 | 1 048 575 |

A run that needs more than `tier.max_cycles()` cycles for its chosen tier is
refused by `build_traces`, not silently truncated.

## What a proof leaks

| Data | Status |
|---|---|
| The program itself | public — `verify` takes it in the clear; `hc` identifies it, it does not hide it |
| Code hash `hc` | public — the preprocessed commitment, binding but not hiding |
| Entry point `pc_entry` | public |
| Gas tier `ℓ` | public per proof (the proof's own size already reveals its trace height, so hiding the tier index buys nothing at the single-proof level; a batch-level histogram, as the whitepaper describes, is a property of the aggregation layer, not of one proof) |
| Eight output words | public |
| Private inputs (`READ_INPUT` values) | hidden — witness only |
| Every register and memory value | hidden |
| Every branch taken | hidden |
| The exact cycle count | hidden — only the padded tier height is visible |
| Which syscalls ran, beyond what the outputs imply | hidden |
| Shielded transfer (`guests::transfer`): the output-commitment digest `H(anchor, nf, cm_out, time)` | public (the eight output words); the ledger is separately handed the plaintext `anchor`/`nf`/`cm_out`/`time` alongside the proof and checks them against the digest — `docs/06-viewing-keys.md`'s "Public outputs" |
| Shielded transfer: the spent commitment `cm_in` | hidden — proved in-circuit (`MERKLE_VERIFY`) against `anchor`, a commitment-tree root, never published itself; only `anchor` (one of the ledger's last 16 roots) and `nf` (a one-way function of `cm_in`) are public, so the link from a note's creation to its spend is not visible on chain |
| Shielded transfer: sender, receiver, amount, asset, note randomness | hidden from the chain; opened by the receiver's or sender's viewing key, or by the transaction key (`docs/06-viewing-keys.md`) |

## The delegated-proving boundary

Proving is out of the circuit's scope by design: the witness is a
`Vec<CycleEvent>` (`emulator::Execution`), and whoever holds it — the
prover, wherever it runs — sees everything: every register, every branch,
every private input. The zero-knowledge property protects the verifier's
view of the proof, not the prover's view of the computation. A confidential
application that cannot trust its own prover needs a separate delegation
story (trusted hardware, MPC, or proving on the data owner's own machine);
this crate does not attempt to solve that, matching the whitepaper's own
remark on the boundary.
