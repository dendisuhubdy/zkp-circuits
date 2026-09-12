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

**M4.2's own measurement, same command, same guest.** The keccak table is in
*every* proof — its height floors at one 32-row block whether or not the
guest ever calls `KECCAK` — so the honest question is what that padding block
costs a guest that does not use it. Measured on `guests::fib` immediately
before and after the M4.2 branch:

| | tier 10 | tier 12 |
| --- | --- | --- |
| proof size, before the keccak table | 437 599 bytes | 460 242 bytes |
| proof size, with it | 1 142 262 bytes | 1 161 162 bytes |
| the padding block's cost | +704 663 bytes (+161%) | +700 920 bytes (+152%) |
| prove time | 5.996 s → 6.154 s | 23.40 s → 23.91 s |
| verify time (first, uncached) | 218.1 ms → 250.6 ms | 812.2 ms → 860.7 ms |

That prove time barely moved is what locates the cost: committing a 32-row
trace is nothing, but every FRI query has to *open* a 2 612-wide main-trace
leaf. Order-of-magnitude, that accounts for most of it — 27 queries x 2 612
columns x 8 bytes is ~565 KB of leaf data, and the zeta/zeta-next opened
values (2 612 columns, two points, a degree-2 extension) another ~84 KB, with
the chip's permutation columns and quotient chunks making up the rest. The
keccak chip's **width**, not its height, is what every proof pays for. Making the table optional (a proof
that declares zero keccak instances rather than one padding block) is the
obvious lever and is not something M4.2 does; `docs/05-roadmap.md` carries it.

A second, smaller number in the same measurement is M4.2's own controller
ruling 1. The first cut of the milestone sized the memory table
`log2_ceil(2^(ℓ+2) + 100·2^(klh−5))`, which doubled it for every proof in
existence (`klh` floors at 5, so the `+100` is never zero). Making the height
proof-declared instead recovers 14 767 bytes and 1.79 s of prove time at tier
10 (1 157 029 → 1 142 262 bytes, 7.94 s → 6.15 s) and 22 316 bytes and 4.65 s
at tier 12 (1 183 478 → 1 161 162 bytes, 28.56 s → 23.91 s).

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

## Private inputs are bound to `H_IN` (M4.1)

Before M4.1, `READ_INPUT idx` (syscall 2) returned whatever word the
prover supplied at that index — a value chosen by the prover, checked by
nothing, and nothing tied two reads of the *same* index together: the
constraint system treated each `READ_INPUT` row independently, so
`READ_INPUT 0` could return one word on one cycle and a different word on
the next with the proof still verifying.

M4.1 closes this. `H_IN` — a Poseidon2 commitment over the guest's whole
private-input vector, computed by `cpu`'s `IS_INDIGEST` rows the same way
`hc` is computed by its `IS_DIGEST` rows (`docs/02-tables-and-buses.md`) —
is bound to a new `input` witness table: every committed word lives on
exactly one table row, and every `READ_INPUT idx` and every unit of the
digest's own absorption draw from that same row through the `input`
table's two buses (`INPUT_DIGEST`, `INPUT_READ`). Two reads of the same
`idx` are now guaranteed to return the same word (both draw from the one
row that index has), and `idx >= n_in` (the committed vector's own
declared length) cannot be satisfied at all — there is no row to draw
from, and the lookup fails to balance.

**What `H_IN` reveals, and what it does not.** `H_IN` is salted (four
witness words, drawn fresh per proof from OS entropy, absorbed as the
first block ahead of the real input words) precisely so it is *hiding* as
well as binding — unlike `hc` (below), a verifier who can enumerate
candidate input vectors gets nowhere testing them against a published
`pv::IN0..7`, since the salt is never published and folds non-invertibly
into the digest (an earlier, unsalted design failed exactly this way: see
`tests/zk.rs`'s `different_private_inputs_same_output_are_indistinguishable_
in_public_values`, which is what caught it). `H_IN` alone does not make
any input word *public* — it only makes repeated reads of the same index
consistent and an out-of-range read unsatisfiable. A guest that wants one
input word to be public (a bytecode commitment, a calldata hash) must
still explicitly `WRITE_OUTPUT` it; nothing about `H_IN`'s own
construction publishes anything beyond the 8-word commitment itself, and
opening that commitment (proving which inputs it commits to) needs the
salt, which never leaves the prover.

Milestone 1's relation is still existential: it proves *"there exist
inputs such that running this program on them produced these outputs,"*
full stop for a general guest — `H_IN` makes the inputs a *fixed, agreed-
upon* vector across the whole execution, but on its own it still binds
nothing outside the proof to a note commitment, a nullifier, or a Merkle
path against a public state root. For everything else, "the balance is
private" means only that the verifier never sees the number, not that the
number is tied to any real account.

The shielded transfer guest additionally binds its own inputs by
recomputing note commitments and a nullifier in-circuit, proving the spent
commitment's membership in the commitment tree (`POSEIDON2`, `NOTE_COMMIT`,
`NULLIFY`, `MERKLE_VERIFY` — `docs/06-viewing-keys.md`), and publishing a
single digest of the result. That is a per-guest choice, not a machine
property (`H_IN`, above, is the machine-level binding every guest gets
for free). Since milestone 3.3, the spent commitment `cm_in` itself is
*not* public — only the tree root (`anchor`) it was proved against is —
so the link from a note's creation to its spend is no longer visible on
chain.

**One remaining gap M4.1 does not close (harmless, not a new leak):** the
shielded-transfer guest's own inputs (`notes::input`) are now *doubly*
bound — once by the machine-level `H_IN`, again by the guest's own
commitment/nullifier logic above. Nothing about the second binding is
weakened by the first, and nothing about the first leaks anything the
second didn't already require the guest to prove; it is simply redundant
coverage of the same private-input vector by two independent mechanisms.

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
proof carries exactly `pv::NUM` (26, since M4.1 added `pv::IN0..IN7` — was
18) public values; every one of them is a
canonical Goldilocks residue (`< p`, so `out0` and `out0 + p` are not two
spellings of the same proof); `public_values[HC0..HC7]` equals the
caller-supplied `hc`, word for word (`public_values[IN0..IN7]`, `H_IN`, is
*not* checked here — it has no caller-supplied counterpart to check
against, unlike `hc`; see "Private inputs are bound to `H_IN`", above);
`public_values[TIER]` equals
`proof.tier`; `proof.tier` is one of the six values in `TIERS` (an
attacker-chosen out-of-range tier is rejected here, before it can be used to
compute a table height and panic); `proof.program_log_height` is within
`[MIN_LOG_HEIGHT, MAX_LOG_HEIGHT]` (review fix — the same defensive pattern,
`VerifyError::ProgramHeight` rather than a panic on an absurd shift);
`proof.input_log_height` is within its own `[MIN_LOG_HEIGHT,
MAX_LOG_HEIGHT]` (M4.1, the `input` table's exact analogue of the same
check); `proof.keccak_log_height` is at least `tables::keccak::
MIN_LOG_HEIGHT` and at most what the declared tier could possibly need
(M4.2, `VerifyError::KeccakHeight` / `KeccakHeightExceedsTier` — a
permutation costs a cycle, so `klh <= tier + 5`, and this is checked before
any table is sized or any verifier key built, which
`tests/cheating.rs::a_keccak_height_past_the_tiers_ceiling_is_rejected_
before_any_verifier_key_is_built` asserts by observing `cached_keys() == 0`
after the rejection); `proof.mem_log_height` is within
`[tier + 2, MAX_MEM_LOG_HEIGHT]` (M4.2 — the memory table's height is
proof-declared now, see "Tiers: what padding hides" below); the
proof's degree bits match the heights that tier (and the four declared
heights) imply for all nine tables; and finally the batch
STARK itself, against a verifier key recomputed from the tier and the
declared heights — `Machine::verifier_key(tier, program_log_height,
input_log_height, keccak_log_height, mem_log_height)`, which includes
the range and nibble tables' preprocessed commitments (256 rows each, since
M2.3 split the 2^16-row byte table in two) and the Poseidon2 chip's
round-constant table. M3.4:
`pc_entry` is no longer independently checked here — the verifier has no
`base_pc` to check it against — it is read out of the proof and bound only
in-circuit, to the digest group's own `pc` (and, indirectly, to `hc` itself,
since `Program::digest` absorbs `base_pc`). `Machine::verifier_key` caches
this by `(tier, program_log_height, input_log_height, keccak_log_height)`
now (M4.1 grew the 2-tuple to a 3-tuple and M4.2's keccak table to a
4-tuple — independent, unrelated height parameters, so a folded single
value would obscure rather than simplify). `mem_log_height` is a parameter
but deliberately *not* a fifth key component: the memory table declares
neither preprocessed nor periodic columns, so the `CommonData` this caches
is identical at every declared memory height (`docs/02`'s degree-budget
section has the argument). Still
program-*content*-independent (review fix: the program table's height is a
value the prover declares per proof, not derived from the tier, so the
cache key needs it too
— `docs/02-tables-and-buses.md`'s "Height" section) —
`tests/e2e.rs::verifier_key_is_cached_after_first_verify` still measures
the cached hit at under 40% of the first, uncached recomputation. Note for
`Machine::verify`'s own signature: it is unchanged by any of this — only
`Proof`'s and `pv`'s shapes grew — so no call site needs a source edit,
only a recompile against the new shapes (see the fullnode sync note at the
end of `docs/superpowers/plans/2026-09-11-zkvm-m4-1.md`).

## Tiers: what padding hides

Trace height never reflects the actual cycle count; it is padded up to the
smallest tier that fits. `cpu` and `alu` pad to `2^ℓ` and `2^(ℓ+1)` rows,
`memory` to **at least** `2^(ℓ+2)` (four cpu-issued accesses per cycle, worst
case — M4.2 makes this a floor rather than the height, since a `KECCAK` row
makes 100 accesses that the keccak chip, not the cpu, sends; see below),
`poseidon2` to
`2^(ℓ+2)` (M3.4: bumped from `2^(ℓ+1)` to fit the program digest's own
`⌈len/4⌉` permutations on top of any guest hashing — `docs/02`'s
`Tier::poseidon2_height` comment has the exact numbers); `program` (M3.4:
now a main table) pads to `1 << Proof::program_log_height` — a value the
*prover* declares per proof from the program's own length, not derived
from the tier at all (review fix: an earlier version of this milestone set
it to `cpu_height()`, unsafe — see `docs/02-tables-and-buses.md`'s
"Height" section under the program table); `keccak` (M4.2) pads to
`1 << Proof::keccak_log_height`, one 32-row block per permutation, floored
at one block and ceilinged at `2^(ℓ+5)`; `memory` (M4.2, controller ruling
1) is proof-declared too — `max(ℓ + 2, log2_ceil(accesses + 1))`, so a guest
whose `KECCAK` calls push it past the tier's four-per-cycle budget grows the
table instead of failing, and every other guest pays exactly the `2^(ℓ+2)`
it always did; `range` and `nibble` are each
always the fixed 256 rows. Padding rows carry `is_real = 0` (or, for
`program`, `valid = 0`) and emit nothing on any bus.

**Two more public numbers, and what they do and do not reveal.**
`keccak_log_height` is an upper bound on the number of `KECCAK`
permutations, rounded up to a power of two — exactly the role
`program_log_height` plays for program size. It is coarse (5 covers 0 or 1
permutations, 6 covers 2, 7 covers 3–4, …) and it floors at 5, so a proof
never reveals that a guest called `KECCAK` *zero* times: a keccak-free guest
and a one-permutation guest declare the same 5.
`mem_log_height`'s tier floor plays the same role for memory traffic: below
`2^(ℓ+2)` accesses the declaration is constant at `ℓ + 2` and says nothing
the tier did not already, and it only starts tracking the real count once a
guest exceeds what the tier already budgeted for.
Digest rows are **not** padding — they are real, `is_real = 1` rows that
count against the tier's cycle budget just like ordinary instructions do
(`Program::digest_rows()` added to `Execution::cycles()` before choosing a
tier).

| Tier `ℓ` | `cpu` rows | `alu` rows | `memory` rows (floor) | max `keccak` rows | max cycles |
|---|---|---|---|---|---|
| 10 | 1 024 | 2 048 | 4 096 | 32 768 | 1 023 |
| 12 | 4 096 | 8 192 | 16 384 | 131 072 | 4 095 |
| 14 | 16 384 | 32 768 | 65 536 | 524 288 | 16 383 |
| 16 | 65 536 | 131 072 | 262 144 | 2 097 152 | 65 535 |
| 18 | 262 144 | 524 288 | 1 048 576 | 8 388 608 | 262 143 |
| 20 | 1 048 576 | 2 097 152 | 4 194 304 | 33 554 432 | 1 048 575 |

A run that needs more than `tier.max_cycles()` cycles for its chosen tier is
refused by `build_traces`, not silently truncated.

## What a proof leaks

| Data | Status |
|---|---|
| The program itself | hidden (M3.4) — `verify` takes only `hc`, never a word of the program; the *prover* still needs the program to build the witness, same as any other private input |
| Code hash `hc` | public — an in-circuit digest (M3.4), binding but not hiding: it still identifies the program to anyone who can guess it |
| Entry point `pc_entry` | public |
| Gas tier `ℓ` | public per proof (the proof's own size already reveals its trace height, so hiding the tier index buys nothing at the single-proof level; a batch-level histogram, as the whitepaper describes, is a property of the aggregation layer, not of one proof) |
| `keccak_log_height` (M4.2) | public — an upper bound on the number of `KECCAK` permutations, rounded up to a power of two, exactly as `program_log_height` is for program size. It floors at 5, so "no permutations" and "one permutation" are indistinguishable; past that it reveals the count to within a factor of two |
| `mem_log_height` (M4.2) | public — the memory table's declared height, floored at the tier's own `2^(ℓ+2)`. Constant, and so uninformative, for every guest whose memory traffic fits what the tier already budgets; above that it bounds the access count to within a factor of two |
| Eight output words | public |
| Private inputs (`READ_INPUT` values) | hidden — witness only; bound (M4.1) to a salted, hiding commitment `H_IN = pv::IN0..IN7` so repeated reads of the same index agree and out-of-range reads are unsatisfiable, but `H_IN` itself opens nothing without the salt (never published) |
| Every register and memory value | hidden |
| Every branch taken | hidden |
| The exact cycle count | hidden — only the padded tier height is visible |
| Which syscalls ran, beyond what the outputs imply | hidden |
| Shielded transfer (`guests::transfer`): the output-commitment digest `H(anchor, nf, cm_out, time)` | public (the eight output words); the ledger is separately handed the plaintext `anchor`/`nf`/`cm_out`/`time` alongside the proof and checks them against the digest — `docs/06-viewing-keys.md`'s "Public outputs" |
| Shielded transfer: the spent commitment `cm_in` | hidden — proved in-circuit (`MERKLE_VERIFY`) against `anchor`, a commitment-tree root, never published itself; only `anchor` (one of the ledger's last 64 roots, `Ledger::ANCHOR_WINDOW`) and `nf` (a one-way function of `cm_in`) are public, so the link from a note's creation to its spend is not visible on chain |
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
