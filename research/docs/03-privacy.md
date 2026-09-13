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

`Machine::new` takes a `FriProfile`: `Production` (80 FRI queries, 20
proof-of-work bits, `max_log_arity: 3` — folding arity 8) or `Test` (16
queries, 4 PoW bits, for a fast `cargo test`). Both use blowup 8 and the same
hiding PCS; only the query count, grinding difficulty, and folding arity
differ.

| | queries | PoW bits | blowup | conjectured | proven (proximity gaps) |
| --- | --- | --- | --- | --- | --- |
| `Production` | 80 | 20 | 8 | `3·80+20 = 260` | ~86 bits |
| `Test` | 16 | 4 | 8 | `3·16+4 = 52` | ~17 bits |

`Production` is the whitepaper's own parameter table (Draft 3, Part III: FRI
80/8/20), **restored on 2026-09-12** after the zk audit (finding ZM1). M2.2
had retuned it to 27 queries, which met the ethSTARK *conjectured* bound
`log_blowup·num_queries + query_pow_bits ≥ 100` (`3·27+20 = 101`) but
silently abandoned the *proven* floor the 80-query choice exists to keep: the
proven proximity-gaps bound is ~86 bits at q=80/g=20 and scales roughly
linearly in the query count, so 27 queries leaves only ~42 proven bits (a
provable 100 would need q=97 or g=34). The paper's Part III reconciliation
weighed exactly that trade and kept q=80/g=20, and this profile is
consensus-facing — genesis-bound through the node's chain config, never
proof-supplied — so it follows the paper. `Test`'s numbers are not a
production target, only fast enough for the suite. Neither profile is any
less zero-knowledge than the other — only proof size and soundness change
with the query count.

**A 27-query proof and an 80-query verifier are mutually incompatible**, in
both directions, so this is a hard fork for proofs: every node in a fleet
must run the same build, and a chain carrying 27-query proofs needs a new
chain id to move.

Measured on `guests::fib` at tier 10 and tier 12 (`cargo test --release
--test e2e measure_production_profile_at_tier_10_and_12 -- --ignored
--nocapture`, `tests/e2e.rs`), immediately before and after the revert on the
same machine:

| | tier 10 | tier 12 |
| --- | --- | --- |
| proof size, 27 queries | 435 529 bytes | 460 441 bytes |
| proof size, 80 queries | **1 202 416 / 1 195 120 bytes** | **1 252 338 / 1 263 921 bytes** |
| prove time (27 → 80) | 5.96 s → 6.05 s, 5.81 s | 22.91 s → 22.78 s, 22.74 s |
| verify time, first and uncached (27 → 80) | 213.2 ms → 232.7 ms, 232.3 ms | 809.2 ms → 837.5 ms, 842.0 ms |

Two consecutive runs are given for the 80-query row for the same reason the
M4.2 table gives two: the hiding PCS draws fresh entropy per proof, so the
postcard encoding moves by about a percent run to run. Proof size grows by
~2.75x, a little under the 80/27 = 2.96 the query count alone suggests
(the parts of a proof that do not scale with queries dilute it). Prove and
first-verify time barely move, for the same reason they barely moved when
M2.2 cut the queries: both are dominated by trace commitment and, for the
first verify, the uncached `verifier_key` recomputation — costs the query
count does not touch.

**Consequence for the node's 1 MiB proof cap.** At 80 queries a *keccak-free*
tier-10 proof is already ~1.20 MB, past the 1 MiB cap the full node applies
to a submitted proof, and a proof carrying the keccak table measures
3 106 757 bytes at tier 10 (a +1.91 MB delta over keccak-free, the 80-query
restatement of the +705 KB M4.2 measured at 27 queries). A proof carrying
M4.4's *sha256* table instead measures 1 603 907 bytes at tier 10 (+400 563 over
the same hash-table-free baseline of 1 203 344, and 1 615 520 for `sha256_demo`,
a guest that genuinely hashes). The cap is the
node's constant, not this crate's, but it has to be raised in the same change
that ships this profile or no production proof will be accepted.

The verify times above are each program's *first* verify on a fresh
`Machine` — an uncached `verifier_key` recomputation, which dominates them
(see "What `verify` actually checks" below); a cached verify of the same
proof runs under 40% of that, per
`tests/e2e.rs::verifier_key_is_cached_after_first_verify`.

**M2.1 → M2.3 history**, kept for the shape of that improvement rather than
as a current baseline (these are 27-query-era or older numbers, on the
pre-M3.4 machine):

| | tier 10 (M2.1 → M2.2 → M2.3) | tier 12 (M2.1 → M2.2 → M2.3) |
| --- | --- | --- |
| proof size | 892 578 → 290 403 → 268 288 bytes | 886 246 → 291 366 → 289 779 bytes |
| prove time | 21.61 s → 20.88 s → 3.11 s | 29.69 s → 29.45 s → 11.44 s |
| verify time (first, uncached) | 2.166 s → 2.148 s → 16.0 ms | 2.178 s → 2.141 s → 18.0 ms |

Those are **M2.3-era** numbers, kept for the M2.1 → M2.3 shape of the
improvement rather than as a current baseline: the M4.2 table below starts from
437 599 bytes at tier 10, not 268 288, because M3.4 (the in-circuit program
digest — digest rows in the cpu table, a proof-declared program-table height)
and M4.1 (the input table, the `INPUT_DIGEST`/`INPUT_READ` buses, the salted
H_IN) each grew every proof in between. `b1d01d9`, this branch's base, is where
that growth had landed when M4.2 began.

**M4.2's own measurement, same command, same guest — at 27 queries.** Every
number in this subsection was taken before the 2026-09-12 profile revert; at
80 queries each of them is roughly 2.75x larger (the keccak delta re-measured
directly: 3 106 757 bytes for a keccak-carrying tier-10 proof against
1 195 120 keccak-free, i.e. +1.91 MB rather than +705 KB). The *shape* of the
comparison — what the optional table buys — is unchanged, which is why the
27-query numbers are kept rather than restated. A 2 612-column table is
expensive in *proof size* regardless of how few rows it holds, because every
FRI query opens a main-trace leaf of the batch's full width. The first cut of
M4.2 put the keccak table in every proof (its height floored at one 32-row
block whether or not the guest called `KECCAK`), and the measurement below is
what that cost. **Task 6 made the table optional** — a guest that makes no
`KECCAK` call declares `keccak_log_height = 0` and the instance is left out of
the batch — and a keccak-free proof is back within about half a percent of its
pre-M4.2 size. Measured on `guests::fib`:

| | tier 10 | tier 12 |
| --- | --- | --- |
| before the keccak table (branch base `b1d01d9`, i.e. M4.1 as shipped) | 437 599 bytes | 460 242 bytes |
| with the padding block every proof carried (Task 5) | 1 142 262 bytes | 1 161 162 bytes |
| keccak-free, the table now optional (Task 6) | **439 816 / 440 456 bytes** | **464 891 / 460 924 bytes** |
| what a guest that *does* call `KECCAK` still pays | +~705 KB (+1.91 MB at 80 queries) | +~701 KB |
| prove time (before / Task 5 / Task 6) | 5.996 s / 6.154 s / 6.48 s, 6.36 s | 23.40 s / 23.91 s / 23.61 s, 25.15 s |
| verify time, first and uncached (before / Task 5 / Task 6) | 218.1 ms / 250.6 ms / 224.3 ms, 219.8 ms | 812.2 ms / 860.7 ms / 827.8 ms, 824.3 ms |

The Task 6 row gives both of two consecutive runs of the same command: the
hiding PCS draws fresh entropy per proof, so the postcard encoding moves by
roughly a percent run to run, which is the same order as the residual gap to
the pre-M4.2 number. The proof also genuinely carries two more declared-height
bytes than it did at `b1d01d9` (`keccak_log_height`, `mem_log_height`).

That prove time barely moved when the table was added is what locates the
cost: committing a 32-row
trace is nothing, but every FRI query has to *open* a 2 612-wide main-trace
leaf. Order-of-magnitude, that accounts for most of it — 27 queries x 2 612
columns x 8 bytes is ~565 KB of leaf data (and 80 queries, the profile
restored on 2026-09-12, ~1.67 MB — the M4.2 numbers in this section are all
27-query numbers, taken before the revert), and the zeta/zeta-next opened
values (2 612 columns, two points, a degree-2 extension) another ~84 KB, with
the chip's permutation columns and quotient chunks making up the rest. The
keccak chip's **width**, not its height, is what a proof carrying it pays for
— which is why Task 6 removes the instance rather than shrinking it: no row
count would have brought a ~300 KB shielded bundle proof plus 705 KB (1.91 MB
at 80 queries) back
under the node's 1 MiB cap.

At `FriProfile::Test` the same comparison is 275 916 bytes at the base
`b1d01d9` (tier 10, `fib(10)`; three runs measured 274 156 / 275 916 /
276 684) against 276 654 bytes here — the number
`tests/e2e.rs::a_keccak_free_proof_carries_no_keccak_table` asserts within 5%,
so a keccak table silently creeping back into keccak-free proofs fails the
suite rather than quietly costing every proof on the chain.

**M4.4's own measurement, at both profiles.** The sha256 chip was built to be
optional from the start, so there is no "every proof pays" row to report — instead
the delta is measured directly, the same guest (`guests::fib(10)`, which makes no
`SHA256` call) at the same tier and the same declared heights, with the instance
in and out. `fib`'s honest sha256 table in the "in" case is one all-padding block,
which is a provable witness (invariant 2: `IS_REAL = 0` zeroes every bus count on
every row) and exactly the shape a non-optional chip would have forced on every
proof:

| tier 10, `fib(10)` | sha256 table absent | one (padding) block | delta |
|---|---|---|---|
| `FriProfile::Test` | 278 670 bytes | 370 977 bytes | **+92 307 bytes** |
| `FriProfile::Production` (80 queries) | 1 203 344 bytes | 1 603 907 bytes | **+400 563 bytes** |

Prove time barely moves (6.130 s → 6.795 s at the production profile), locating the
cost where keccak's is: opening a 476-column leaf at each of 80 FRI queries, not
committing a 64-row trace. +0.40 MB against keccak's +1.91 MB is a ratio of 0.21,
close to the 476/2 711 column ratio — the arithmetic `docs/04-guests.md` asked this
chip to plan against. `tests/e2e.rs::
a_declared_sha256_table_costs_about_a_hundred_kilobytes_at_the_test_profile` keeps
the Test-profile number honest in the suite;
`measure_the_sha256_table_cost_at_the_production_profile` (`#[ignore]`d) is where
the production row comes from.

A second, smaller number in the same measurement is M4.2's own controller
ruling 1. The first cut of the milestone sized the memory table
`log2_ceil(2^(ℓ+2) + 100·2^(klh−5))`, which doubled it for every proof in
existence (`klh` floored at 5 then, so the `+100` was never zero). Making the height
proof-declared instead recovers 14 767 bytes and 1.79 s of prove time at tier
10 (1 157 029 → 1 142 262 bytes, 7.94 s → 6.15 s) and 22 316 bytes and 4.65 s
at tier 12 (1 183 478 → 1 161 162 bytes, 28.56 s → 23.91 s).

M2.2 (80 → 27 queries, retuned to the 100-bit conjectured target — since
reverted, see the profile table above) cut proof
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
`proof.tier`; and then — all of it in `machine::check_declared_heights`, which
`verify` calls before it sizes anything, and which is a free function over the
declared values precisely so these bounds can be tested at tiers no test could
afford to prove at — `proof.tier` is one of the six values in `TIERS` (an
attacker-chosen out-of-range tier is rejected here, before it can be used to
compute a table height and panic); `proof.program_log_height` is within
`[MIN_LOG_HEIGHT, MAX_LOG_HEIGHT]` (review fix — the same defensive pattern,
`VerifyError::ProgramHeight` rather than a panic on an absurd shift);
`proof.input_log_height` is within its own `[MIN_LOG_HEIGHT,
MAX_LOG_HEIGHT]` (M4.1, the `input` table's exact analogue of the same
check); `proof.keccak_log_height` is either `0` — M4.2 Task 6's "this proof has no
keccak table", exempt from the range check because there is no height to
check — or within `[tables::keccak::MIN_LOG_HEIGHT,
tables::keccak::MAX_LOG_HEIGHT]` *and* no larger than what the declared tier
could possibly need (M4.2, `VerifyError::KeccakHeight` /
`KeccakHeightExceedsTier` — a permutation costs a cycle, so `klh <= tier + 5`,
capped absolutely at 20; the tier half alone would let a tier-20 header ask for
a 2^25-row preprocessed keccak trace, which is why the Task 5 review put the
flat cap back. Both are checked before any table is sized or any verifier key
built, which
`tests/cheating.rs::a_keccak_height_past_the_tiers_ceiling_is_rejected_
before_any_verifier_key_is_built` and its `..._past_the_absolute_cap_...`
sibling assert by observing `cached_keys() == 0` after the rejection);
`proof.sha256_log_height` gets the identical treatment (M4.4,
`VerifyError::Sha256Height` / `Sha256HeightExceedsTier`) — `0` means "no sha256
table", any other value must lie in `[tables::sha256::MIN_LOG_HEIGHT,
tables::sha256::MAX_LOG_HEIGHT] = [6, 20]` and be no larger than
`Tier::max_sha256_log_height`, which is `min(tier + 6, 20)` since a compression
costs a cycle and fills one 64-row block; that method folds the flat cap in
rather than leaving it to each caller, which is the one place M4.4 deliberately
spells a bound differently from M4.2;
`proof.mem_log_height` is within
`[tier + 2, MAX_MEM_LOG_HEIGHT]` (M4.2 — the memory table's height is
proof-declared now, see "Tiers: what padding hides" below; both ends are
pinned by `tests/cheating.rs`, the ceiling since the Task 5 review); the
proof's degree bits match the heights that tier (and the five declared
heights) imply for all eight tables — nine or ten when `keccak_log_height` and
`sha256_log_height` are non-zero — and
since that comparison is of whole lists it is simultaneously the check that
the batch has the right *number* of instances for what the proof declares;
and finally the batch
STARK itself, against a verifier key recomputed from the tier and the
declared heights — `Machine::verifier_key(tier, program_log_height,
input_log_height, keccak_log_height, sha256_log_height)`, which includes
the range and nibble tables' preprocessed commitments (256 rows each, since
M2.3 split the 2^16-row byte table in two) and the Poseidon2 chip's
round-constant table. M3.4:
`pc_entry` is no longer independently checked here — the verifier has no
`base_pc` to check it against — it is read out of the proof and bound only
in-circuit, to the digest group's own `pc` (and, indirectly, to `hc` itself,
since `Program::digest` absorbs `base_pc`). `Machine::verifier_key` caches
this by `(tier, program_log_height, input_log_height, keccak_log_height,
sha256_log_height)`
now (M4.1 grew the 2-tuple to a 3-tuple, M4.2's keccak table to a
4-tuple and M4.4's sha256 table to a 5-tuple — independent, unrelated height
parameters, so a folded single
value would obscure rather than simplify). `keccak_log_height = 0` is an
ordinary value of that fourth component and a genuinely distinct key: it
selects the eight-chip batch, whose preprocessed commitment omits the keccak
table's 99 periodic columns entirely; `sha256_log_height` is the same story for
the 10 periodic columns of M4.4's chip, and the two are independent, so the four
combinations are four keys. **The arity change is a vendoring-visible one:** the
fullnode's `deploy/sync-zkvm.sh` anchors on this function's signature, so
re-vendoring this constraint set has to update it (that update is not made here —
this plan does not re-vendor the node). `mem_log_height` is deliberately *not* a
sixth key component — nor, since the M4.2 review, a parameter at all: the
memory table declares neither preprocessed nor periodic columns, so the
`CommonData` this caches is identical at every declared memory height
(`docs/02`'s degree-budget section has the argument), and the function feeds
`log_ext_degrees` the tier's own floor. The declared `mem_log_height` is still
checked, just elsewhere: by `check_declared_heights` and by the `degree_bits`
list comparison above. Still
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
"Height" section under the program table); `keccak` (M4.2) is **absent entirely** unless the guest calls `KECCAK`, and
otherwise pads to
`1 << Proof::keccak_log_height`, one 32-row block per permutation, floored
at one block and ceilinged at `2^(ℓ+5)`; `sha256` (M4.4) is absent or present on
exactly those terms, padding to `1 << Proof::sha256_log_height`, one 64-row block
per compression, floored at one block and ceilinged at `min(2^(ℓ+6), 2^20)`;
`memory` (M4.2, controller ruling
1) is proof-declared too — `max(ℓ + 2, log2_ceil(accesses + 1))`, where the
access count is `4·cycles + 100·n_keccak + 32·n_sha256`, so a guest
whose `KECCAK` or `SHA256` calls push it past the tier's four-per-cycle budget
grows the table instead of failing, and every other guest pays exactly the
`2^(ℓ+2)` it always did; `range` and `nibble` are each
always the fixed 256 rows. Padding rows carry `is_real = 0` (or, for
`program`, `valid = 0`) and emit nothing on any bus.

**Two more public numbers, and what they do and do not reveal.**
`keccak_log_height` is an upper bound on the number of `KECCAK`
permutations, rounded up to a power of two — exactly the role
`program_log_height` plays for program size. Above zero it is coarse (5
covers 1 permutation, 6 covers 2, 7 covers 3–4, …), so it bounds the count to
within a factor of two and no better. **`0` is exact, and it is the one
disclosure this number makes precisely: "this program made no `KECCAK` call
at all"** (M4.2, Task 6). That is deliberate, and it is the same class of leak
`program_log_height` already is — a coarse structural fact about the
*program*, not about its data: a verifier learns that this guest does not
hash, exactly as it already learns roughly how long the guest is. It is paid
for: a keccak-free proof drops the 2 612-column keccak table from the batch
and is ~1.91 MB smaller at the production profile (~705 KB at the 27 queries
M4.2 measured), which is the difference
between a shielded bundle proof fitting the node's 1 MiB cap and not.
Through the first cut of M4.2 the height floored at 5 and "zero" and "one"
were indistinguishable; that indistinguishability cost every proof on the
chain the full table, and was traded away knowingly.
`sha256_log_height` (M4.4) says all of that again for `SHA256` compressions, at
a quarter of the price: the chip is 466 + 10 columns against keccak's 2 612 + 99,
so the table it lets a non-hashing guest drop is worth ~92 KB at
`FriProfile::Test` and ~400 KB at the production profile (measured, same guest,
same tier, instance in versus out — `docs/02`'s `sha256` section has the table).
The two declarations are independent, so a proof publishes which of the two hash
syscalls its program uses, each to within a factor of two above zero and exactly
at zero.
`mem_log_height`'s tier floor plays the same role for memory traffic: below
`2^(ℓ+2)` accesses the declaration is constant at `ℓ + 2` and says nothing
the tier did not already, and it only starts tracking the real count once a
guest exceeds what the tier already budgeted for.
Digest rows are **not** padding — they are real, `is_real = 1` rows that
count against the tier's cycle budget just like ordinary instructions do
(`Program::digest_rows()` added to `Execution::cycles()` before choosing a
tier).

| Tier `ℓ` | `cpu` rows | `alu` rows | `memory` rows (floor) | max `keccak` rows | max `sha256` rows | max cycles |
|---|---|---|---|---|---|---|
| 10 | 1 024 | 2 048 | 4 096 | 32 768 | 65 536 | 1 023 |
| 12 | 4 096 | 8 192 | 16 384 | 131 072 | 262 144 | 4 095 |
| 14 | 16 384 | 32 768 | 65 536 | 524 288 | 1 048 576 | 16 383 |
| 16 | 65 536 | 131 072 | 262 144 | 2 097 152 | 1 048 576 | 65 535 |
| 18 | 262 144 | 524 288 | 1 048 576 | 8 388 608 | 1 048 576 | 262 143 |
| 20 | 1 048 576 | 2 097 152 | 4 194 304 | 33 554 432 | 1 048 576 | 1 048 575 |

The `sha256` column flattens at `2^20` from tier 14 up because
`Tier::max_sha256_log_height` folds the flat `tables::sha256::MAX_LOG_HEIGHT = 20`
into the tier relation: 16 384 compressions is ~1 MiB of hashed message, past
anything this crate proves, and an untrusted `u8` must not be able to make a
verifier build more (`docs/02`'s `sha256` section).

A run that needs more than `tier.max_cycles()` cycles for its chosen tier is
refused by `build_traces`, not silently truncated.

## What a proof leaks

| Data | Status |
|---|---|
| The program itself | hidden (M3.4) — `verify` takes only `hc`, never a word of the program; the *prover* still needs the program to build the witness, same as any other private input |
| Code hash `hc` | public — an in-circuit digest (M3.4), binding but not hiding: it still identifies the program to anyone who can guess it |
| Entry point `pc_entry` | public |
| Gas tier `ℓ` | public per proof (the proof's own size already reveals its trace height, so hiding the tier index buys nothing at the single-proof level; a batch-level histogram, as the whitepaper describes, is a property of the aggregation layer, not of one proof) |
| `keccak_log_height` (M4.2) | public — an upper bound on the number of `KECCAK` permutations, rounded up to a power of two, exactly as `program_log_height` is for program size: above zero it reveals the count to within a factor of two. `0` is exact and means "this program made no `KECCAK` call" (M4.2, Task 6 — the proof then carries no keccak table at all, which is what makes it ~1.91 MB smaller at the production profile, ~705 KB at the 27 queries M4.2 measured); the same class of structural, program-shaped leak `program_log_height` is |
| `sha256_log_height` (M4.4) | public — the same thing for `SHA256` compressions (64-row blocks, so `6` covers 1, `7` covers 2, `8` covers 3–4, …). `0` is exact and means "this program made no `SHA256` call", and is what lets the proof drop the 466-column sha256 table: ~92 KB at `FriProfile::Test`, ~400 KB at the production profile. Independent of `keccak_log_height`, so the pair says which of the two hash syscalls the program uses |
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
| sBPF call (`guests::compiled::sbpf`, M4.4): the Solana program, the instruction, the accounts and their post-state | hidden — the ELF and the serialized instruction are `READ_INPUT` values bound to `H_IN`, and the eight output words are a status word plus a 224-bit Poseidon2 digest over three SHA-256 digests (`program_hash`, `input_hash`, `output_hash`), so the chain learns neither which program ran nor over what. A verifier who *already has* the program and the instruction can recompute all three and confirm the run; one who does not learns only the status |
| sBPF call: the status word | public, three-valued and deliberately coarse — `1` the program returned `r0 == 0`, `0` it returned some `ProgramError`, `2` an exceptional halt. The **error code is not published** (the seven digest words are spoken for), and `0` and `2` both bind the *pre*-state as the post-state, so a failed call is indistinguishable from a call that did nothing |
| sBPF call: how much work it did | leaked, to within a factor of two, by `sha256_log_height` and the tier — and more than for other guests, because M4.4 hashes the ELF in-circuit: `sha256_log_height` is essentially `log2(program size / 64)`, so it bounds the *size of the program that ran*. Note that this is the **cost of the binding being sound**, not an oversight: because `H_IN` is hiding (above), a `program_hash` the guest does not recompute would be bound to nothing at all, so the in-circuit hashing cannot simply be dropped (`docs/04-guests.md`, "What does *not* work"). Of the two sound remedies there, (A) baking the ELF into the guest's data segment removes this leak but replaces it with a larger one — `hc` then identifies the *program*, not just the interpreter — and (B) a public input segment publishes the ELF words outright. A hiding program commitment is the open item that would fix all three (`hc` is binding but not hiding, above) |

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
