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

## `hc` is now an in-circuit digest — the verifier never holds the program

Through M3.3, `hc` was the preprocessed program table's Merkle root, and the
verifier held the whole `Program` in the clear to recompute it — so the
section below (still accurate as *history*) argued `hc` was "binding, not
hiding" for the boring reason that there was nothing left to hide once the
verifier already had every word. M3.4 changes the mechanism: `program` is a
witness trace now (`docs/02-tables-and-buses.md`'s in-circuit decoder), and
`hc` is a Poseidon2 sponge computed by `cpu`'s digest-row prefix and pinned
to `pv::HC0..HC7` — `Machine::verify(hc, proof)` takes the digest directly,
never the program.

**What that does and doesn't change about what `hc` leaks.** `hc` still
identifies a program — `Program::digest()` is a pure, deterministic function
of `base_pc` and every word, so anyone who can guess a candidate program can
still recompute `hc` and confirm the guess, and two deployments of the same
program still produce the same `hc` and are still trivially linkable. That
part of "binding, not hiding" is unchanged, and for the same underlying
reason: `hc` has no independent salt of its own, in-circuit or out. What
*has* changed is where the hiding gap actually lives. Before M3.4, the gap
was "the verifier holds the program in the clear" — a much larger leak than
`hc` alone, and the reason the M1 framing above was correct to call program
confidentiality "not a milestone-1 property" at all. After M3.4, the
verifier holds *only* `hc` (an 8-word digest) and never sees a single
instruction word — a real privacy gain — but `hc` itself is still not
hiding: nothing about the *digest's own construction* blinds it, so a
verifier who can enumerate candidate programs (a small fixed set of known
guest binaries, say) can still test each one against a published `hc`. A
genuinely hiding program commitment — a fresh per-deployment salt folded
into the digest, checked in-circuit against a value the guest itself
attests to — is not something this milestone adds; `hc` is exactly as
guessable as it always was, just now guessed against a smaller, in-circuit
witness instead of a publicly-held one.

**What makes `hc` bind the *whole* program, not just a prefix.** Calling
`hc` "binding" is only as strong as what the digest rows actually absorb.
`tables::program`'s `MULT_WORD` (the `PROGRAM_WORD` bus multiplicity) is
constrained to equal `VALID` exactly, not merely zeroed on invalid rows —
so every real, decodable instruction the program table holds supplies
exactly one `(pc, word)` copy to the bus the digest rows draw from, never
zero. `PROGRAM_WORD`'s LogUp balance then forces a set-equality: the `len`
messages the digest rows demand (one per `base_pc + 4·j`, `j < len`) must
coincide exactly with the set of valid rows' own `pc` values. A weaker,
one-sided gate (`mult_word · (1 − valid) = 0`, the first cut of M3.4) would
let a valid row opt out of the digest while staying executable — reachable
by a computed jump past the digested window, say — so `hc` would bind only
a *declared* prefix of the program, not the executable program as a whole,
undermining "binding" as a security property even though `hc` still looked
like a deterministic function of *something*. `src/tables/program.rs`'s
module doc ("`hc` binds the whole executable program") and
`docs/02-tables-and-buses.md`'s "`hc` binds the whole executable program"
section have the full LogUp argument; `tests/cheating.rs`'s
`an_undigested_reachable_program_tail_is_rejected` is the regression.

The preprocessed tables that remain (`range`, `nibble`, the Poseidon2
round-constant table) are the ones M3.4's "no salt to hide" argument now
actually applies to cleanly: they are fixed, program-independent data, so
`Machine::verifier_key`'s deterministic salt (`machine::KEY_SEED`, replacing
the old program-derived one) hides nothing because there is nothing
program-specific left in what it salts.

## What `verify` actually checks

`Machine::verify(hc, proof)` — the code a node runs — checks, in order: the
proof carries exactly `pv::NUM` (18) public values; every one of them is a
canonical Goldilocks residue (`< p`, so `out0` and `out0 + p` are not two
spellings of the same proof); `public_values[HC0..HC7]` equals the
caller-supplied `hc`, word for word; `public_values[TIER]` equals
`proof.tier`; `proof.tier` is one of the six values in `TIERS` (an
attacker-chosen out-of-range tier is rejected here, before it can be used to
compute a table height and panic); `proof.program_log_height` is within
`[MIN_LOG_HEIGHT, MAX_LOG_HEIGHT]` (review fix — the same defensive pattern,
`VerifyError::ProgramHeight` rather than a panic on an absurd shift); the
proof's degree bits match the heights that tier (and the declared program
height) imply for all seven tables; and finally the batch STARK itself,
against a verifier key recomputed from the tier and the declared program
height — `Machine::verifier_key(tier, program_log_height)`, which includes
the range and nibble tables' preprocessed commitments (256 rows each, since
M2.3 split the 2^16-row byte table in two) and the Poseidon2 chip's
round-constant table. M3.4:
`pc_entry` is no longer independently checked here — the verifier has no
`base_pc` to check it against — it is read out of the proof and bound only
in-circuit, to the digest group's own `pc` (and, indirectly, to `hc` itself,
since `Program::digest` absorbs `base_pc`). `Machine::verifier_key` caches
this by `(tier, program_log_height)` now — still program-*content*-
independent (review fix: the program table's height is a value the prover
declares per proof, not derived from the tier, so the cache key needs both
— `docs/02-tables-and-buses.md`'s "Height" section) —
`tests/e2e.rs::verifier_key_is_cached_after_first_verify` still measures
the cached hit at under 40% of the first, uncached recomputation.

## Tiers: what padding hides

Trace height never reflects the actual cycle count; it is padded up to the
smallest tier that fits. `cpu` and `alu` pad to `2^ℓ` and `2^(ℓ+1)` rows,
`memory` to `2^(ℓ+2)` (four accesses per cycle, worst case), `poseidon2` to
`2^(ℓ+2)` (M3.4: bumped from `2^(ℓ+1)` to fit the program digest's own
`⌈len/4⌉` permutations on top of any guest hashing — `docs/02`'s
`Tier::poseidon2_height` comment has the exact numbers); `program` (M3.4:
now a main table) pads to `1 << Proof::program_log_height` — a value the
*prover* declares per proof from the program's own length, not derived
from the tier at all (review fix: an earlier version of this milestone set
it to `cpu_height()`, unsafe — see `docs/02-tables-and-buses.md`'s
"Height" section under the program table); `range` and `nibble` are each
always the fixed 256 rows. Padding rows carry `is_real = 0` (or, for
`program`, `valid = 0`) and emit nothing on any bus.
Digest rows are **not** padding — they are real, `is_real = 1` rows that
count against the tier's cycle budget just like ordinary instructions do
(`Program::digest_rows()` added to `Execution::cycles()` before choosing a
tier).

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
| The program itself | hidden (M3.4) — `verify` takes only `hc`, never a word of the program; the *prover* still needs the program to build the witness, same as any other private input |
| Code hash `hc` | public — an in-circuit digest (M3.4), binding but not hiding: it still identifies the program to anyone who can guess it |
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
