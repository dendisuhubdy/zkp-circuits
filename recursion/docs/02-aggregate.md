# 02 — The aggregate program: N bundle proofs in one rVM proof, and what it costs

M5.3 (plan: `docs/superpowers/plans/2026-09-15-zkvm-m5-3.md`; the machine and its single-proof
numbers: `docs/01-rvm-machine.md`). One **N-generic aggregate program per inner shape** (R1):
a counted loop over the tape's `N`, each iteration the single-proof verifier's phases 0–7 over
that proof's tape region with a fresh challenger (R2), then the interface digest over
`[inner_vk_digest ‖ N ‖ B(8) ‖ 35·N]` (R5; the eight binding words B are audit v3's AGG-2
amendment, below). The fullnode registers one program digest per inner shape
(R6); the program covers every `N` the tape holds, because the loop count is a tape value, not a
build-time constant.

Every number below was measured on 2026-09-15 on this machine (macOS, 16 cores, 48 GB) with the
crate's documented command and is pinned by a test where the plan asks for one: the per-N cycle
numbers in `tests/pins.json` (`tests/aggregate.rs::the_per_n_cycle_budget_is_pinned`), the N=1
differential and the tamper table in the same file, the stub vectors in
`the_admission_stub_vectors`. Estimates are labelled with their derivation.

**Current numbers (2026-10-05): phase 3, "Phase 3" below and `docs/06-phase3-fold-reduce.md`.**
Production N=1 at tier 20 (585 960 rows), N=2 and N=3 at 21, N=4 at 22; the test N=1/2/3 at
18 / 19 / 19; the register table one height shorter at every production N and at test N=1 and 2 (test N=3
stays at `2^21`), the RAM table one height shorter at production N=1, 2 and 4 (production N=3 stays
at `2^23`) and at no test N; the aggregate program digest moved again. Phase 2's row cuts (2026-10-03, "Phase 2" below and `docs/04-phase2-row-cuts.md`) made
every rung one tier lower at equal N (production N=1 at tier 20, 893 880 rows). The sections in
between are the record of how the earlier numbers were arrived at.

## AGG-2: the aggregate binding (audit v3, amended 2026-09-25)

Before this amendment the interface was `[vk ‖ N ‖ 34·N]` and said nothing about who made the
proof: a registered aggregator could take another's valid aggregate, re-sign the transaction
under its own identity and nonce, and be paid for it. The program now hints eight binding words
straight after `N` and absorbs them into the interface sponge between `N` and the public values,
so the published digest covers `[vk(4) ‖ N ‖ B(8) ‖ 35·N]` with
`B = H("rand-aggregate-bind-1", chain_id ‖ aggregator ‖ nonce)`, derived in `randprotocol-core`.
Eight words are exactly two rate fills, so the absorb schedule after them is the one the count
word alone left. (The unconditional final permutation is sound for every length only since
constraint set 8's deferred absorb — the section below.)

- `aggregate(…, binding, …)` proves under the caller's own triple.
- `verify_aggregate(…, binding)` takes the chain's *own* recompute from the transaction and
  refuses a list carrying any other words (`BindingMismatch`) before the digest check. A list
  whose words are rewritten to match fails the digest (`DigestMismatch`), because the program
  absorbed the prover's words.
- The self-verifier (`rv32r`) carries the outer transaction's binding the same way:
  `[rvm_vk ‖ 1 ‖ B(8) ‖ 4]`, over the tape `WitnessTape::build_for_with_binding`.
- Cost: +80 cpu rows, +2 permutations, +74 memory accesses, +8 witness words, the same at every
  N (preamble only). Rows are now `408 + N · 441 454 + 4·⌊N/2⌋` and the tape is `9 + 43 344·N`
  words. The pins are in `tests/pins.json`, and `LOOP_OVERHEAD` is 219. The tables below are the
  M5.3 measurements from before the binding.
- The program digest changes, so the fullnode re-vendors and re-pins `aggregate_program_digest`.
  **The production proof batch must use this program** (the fullnode's audit-v3 plan, task C4).

## VERIFIER-1: the re-pin (2026-09-28, constraint set 7, chain 16, v0.6.1)

The per-proof pipeline (`rv32.rs`'s `emit_proof`, shared by `rv32`, `rv32n` and `rv32r`) now
asserts each FRI commit-phase proof-of-work word is the honest `0` (`docs/00-recursion-vm.md`,
"Segment 7's PoW words"). That adds one `JEQ` and one trap per FRI round to the program, so every
program digest moves; the transcript, the tape and every other cost do not. Cost per verified
proof: +1 cpu row and +2 instructions per FRI round — +9 / +18 at the constraint-set-7 bundle
shape's nine rounds (test and production alike; the `2^7` floor added the ninth), +5 / +10 and
+9 / +18 at the self-verifier's two fixture shapes.

It lands in the same constraint set as the inner machine's changes (the LogUp blind and `2^7`
floor, ZKM-1's 32-bit lanes, HCS-1's key salts), so the pins below are measured once, on the
integrated `feat/cs7` tree; "before" is constraint set 6.

| pin | constraint set 6 | constraint set 7 with VERIFIER-1 |
|---|---|---|
| `aggregate_program_digest`, production bundle shape (what a chain's aggregation section pins) | `e0578970a1981321e044a6bbb947210b79d102daf1083c9b53b752a185709108` | `66a8094f19f8b1b47177a611e065d88c5ba27e100b5189d485cd28f09345356d` |
| `aggregate_program_digest`, test fixture shape (`tests/verifier.rs`) | `1ec0c545003179b1ca4215b439d2d69fa33149a5257a04dc8473030fc2deeeeb` | `5e04fba0c0b900dcafbf37aa0acae87afb9ba2269f4d1970706ce2320b962993` |
| single-proof program, production (`src/programs/verify_rv32.digest`) | `8901cec9c1681c9674f1e5582805d625c60b20d9f69be546da982622f36e0bda` | `8f15919989c3975106b7663722fe892c20e14e9658948e073626662cc999e1e7` |
| single-proof program, test shape | `71f2a93d2033c7c80ed4b5bb7311251eb4c7aa1d9729baa51a8f5f670933b8d8` | `e1ed7d054b6bfd240c4192be6c8ce92d137f292031138bcbbd89daf6d34ae35a` |
| Off replay, test shape (`tests/verifier.rs`) | `c1c04ac3a9faf266eb8980260dae6c7f12fe9ee4cf3dfa40de8440182258d731` | `aafb158456ff7e7ed742b48197b6fc3eb4925a0b2ae1a7ed3717bfb676cd38ea` |
| self-verifier (`self_program_digest`), toy fixture shape (`tests/self_verify.rs`, newly pinned) | `c18fa9eadf161ab625fc23048a6bcd4020eea8eaac33720d34e17f7148cd4804` | `6b2f058e60ffdf6a77091b932710513191688e4bdc59b2ecdc65b0dd5039033b` |
| self-verifier cost, toy (rows, perms, mem, instrs, witness) | (276555, 7498, 405853, 278398, 29575) | (276560, 7498, 405853, 278408, 29575) |
| self-verifier cost, busy | (368761, 9132, 481628, 370864, 35407) | (368770, 9132, 481628, 370882, 35407) |
| `pins.json` production cpu rows / instructions | 1 968 619 / 1 978 422 | 2 044 506 / 2 054 639 |
| `pins.json` aggregate test N=1/2/3 cpu rows | 441 862 / 883 320 / 1 324 774 | 461 302 / 922 203 / 1 383 100 |

VERIFIER-1 alone does not move `inner_vk_digest` (the admission stub vector above: it is the
inner machine's key, not the program) nor `LOOP_OVERHEAD`; constraint set 7's inner changes do
move the inner key. The self-verifier's costs are the rVM's own fixtures, which no inner change
touches. The fullnode re-vendors the rVM and re-pins `aggregate_program_digest` at the chain-16
cut; no live chain carries an aggregation section, so nothing live moves. **The production proof
batch must use this program.**

## Constraint set 8: 35 public values per inner proof, and the deferred absorb (2026-09-29, chain 18)

The inner machine appends `GAS` (`pv::GAS = 34`, the declared gas limit) to its public values:
`pv::NUM = 35`, and the interface is `[vk(4) ‖ N ‖ B(8) ‖ 35·N]`. `interface_words(_bound)` and
the programs read `shape.num_public_values()`, so the list widens with no code change — except
in one place the old width was load-bearing.

**The double final permutation.** `rv32n`'s interface sponge used to permute *eagerly* (on the
word that filled the rate) and then permute once more, unconditionally, after the last word.
That is the host's `public_digest` only when the list never ends on a block boundary: at 34
words a proof, `(13 + 34N) mod 4 ∈ {1, 3}`, never `0`. At 35, `(13 + 35N) mod 4 = (1 + 3N) mod
4` is `0` for every `N ≡ 1 (mod 4)` — `N = 1` included (48 words) — where the program permuted
twice and published a digest no honest recompute matches: every `N = 1, 5, 9, …` aggregate
would have been refused (`DigestMismatch`), never wrongly accepted. Found red on the cs8 fixtures
(`n1_aggregate_publishes_the_bound_interface_digest_at_a_pinned_overhead`: left
`[12767509755616455779, …]`, right `[12462977045447092106, …]`). Fixed in `dsl::hash::
absorb_staged`: the permutation is deferred to the word that opens the next block, so a block
is always pending after the last word and the one final permutation is right for every length.
`tests/dsl.rs::the_staged_absorb_is_the_host_sponge_at_every_length` pins it against
`public_digest` at lengths 1–24, proof-free (red at length 4 on the eager absorb). Cost: one
cursor reload per staged word (`8 + 35·N`), minus the doubled permutation's four rows where it
used to happen.

| pin | constraint set 7 with VERIFIER-1 | constraint set 8 |
|---|---|---|
| `aggregate_program_digest`, production bundle shape (what a chain's aggregation section pins) | `66a8094f19f8b1b47177a611e065d88c5ba27e100b5189d485cd28f09345356d` | `1831f036a2d3524249df17a66a220457878f8aeed669c77db08d58026461ddd7` |
| `aggregate_program_digest`, test fixture shape (`tests/verifier.rs`) | `5e04fba0c0b900dcafbf37aa0acae87afb9ba2269f4d1970706ce2320b962993` | `9eba73805fa23361708d9ca1c58d904ac830aeb6810470ec7788c4f36880193d` |
| single-proof program, production (`src/programs/verify_rv32.digest`) | `8f15919989c3975106b7663722fe892c20e14e9658948e073626662cc999e1e7` | `454592b35ccfd6feefe93b7d2353bc484fca8ff260f74deae4e0865f7da2f2b3` |
| Off replay, production shape (`tests/verifier.rs`) | `aafb158456ff7e7ed742b48197b6fc3eb4925a0b2ae1a7ed3717bfb676cd38ea` | `af7728191e4ec0c1b8f6cc3d60aff36b04dc0d1b48b494aa9fbf107ebc708425` |
| `inner_vk_digest`, test fixture shape (the stub vector above) | `ee072b7a8eb766c7de6fb4fffa1f9f1b6098c8971b1b49eec2f4e0091edadfbe` | `346ee1841980e46a3501f5b04cdf40dd3208e5b1c67360285353cf7a0b735fb9` |
| `pins.json` production cpu rows / permutations / instructions | 2 044 506 / 54 428 / 2 054 639 | 2 047 268 / 54 515 / 2 057 401 |
| `pins.json` aggregate test N=1/2/3 cpu rows | 461 302 / 922 203 / 1 383 100 | 462 262 / 924 115 / 1 385 968 |
| `LOOP_OVERHEAD` (test and production alike) | 220 | 274 (235 on the eager absorb) |
| test-profile single proof, permutations (`tests/verifier.rs`) | 11 852 | 11 875 |
| production N=1 aggregate, cpu rows (tier) | 2 044 726 (21; pin + overhead) | 2 047 542 (21; 49 610 rows under `2^21`) |

The self-verifier's digests and costs (`tests/self_verify.rs`) do not move: its fixtures are the
rVM's own.

**The final review's `gas_max` fix** (the absorb rows' `2^(t−2)` term) moves only the inner
proofs' *value* of `GAS` — a fixture proof's default limit goes `16383 → 20479` — never the inner
shape, key or AIR. Re-run on a regenerated cache, nothing in the table above moves: both
`aggregate_program_digest`s (production `1831f036…ddd7`, test `9eba7380…193d`), the committed
single-proof digest, the Off replay, the `inner_vk_digest`, every `pins.json` row count and
`LOOP_OVERHEAD` all reproduced unchanged. What moves is what rides on the values: the stub
vector's interface list (GAS words `0x3fff → 0x4fff`; the notes are random per cache anyway) and
its digest (`36b414c0…f5dd → 5e3d7fb2…1ed6`). The fullnode re-vendors and re-pins `aggregate_program_digest` at the chain-18 cut;
no live chain carries an aggregation section. **The production proof batch must use this
program**, and every number above is an emulation measured on the 48 GB laptop (2026-09-29); the rVM
*proofs* — the tier-19 round trip (`two_test_profile`), the one-proof round trip, the N=3 twin and
the production exits — were not re-run for cs8 here: they need the ≥ 64 GB box.

## Phase 2: the three row cuts (2026-10-03)

Cut A (opened rows hinted straight into per-height-group sponge buffers; the tape's segment 11 in
height-group order), Cut B (`HINTN`, opcode 26) and Cut C (`COMPRESS`, opcode 27) — the record,
per-stage measurements and the prover's live-heap finding are `docs/04-phase2-row-cuts.md`. The
interface `[vk ‖ N ‖ B(8) ‖ 35·N]`, the binding, `verify_aggregate`'s API, the `inner_vk_digest`
and the admission stub's list and digest do **not** move; the program does.

| pin | constraint set 8 | phase 2 |
|---|---|---|
| `aggregate_program_digest`, production bundle shape (what a chain's aggregation section pins) | `1831f036a2d3524249df17a66a220457878f8aeed669c77db08d58026461ddd7` | `c90b3f0a7758c7e306042f27a94cc1f123441b0284c7352cb3f426048c7a74d8` |
| `aggregate_program_digest`, test fixture shape (`tests/verifier.rs`) | `9eba73805fa23361708d9ca1c58d904ac830aeb6810470ec7788c4f36880193d` | `5f1f69010b8aa4cbb6072ffd8a631fa05897c18ed3663ae2bcd136455d2612df` |
| single-proof program, production (`src/programs/verify_rv32.digest`) | `454592b35ccfd6feefe93b7d2353bc484fca8ff260f74deae4e0865f7da2f2b3` | `723218da65a50f1f1581013f79fa5c5b1816b7ab46796dbaa4672c52bce2d0d1` |
| Off replay, production shape (`tests/verifier.rs`) | `af7728191e4ec0c1b8f6cc3d60aff36b04dc0d1b48b494aa9fbf107ebc708425` | `39bb6b8d94e62dd282001384d0b65294e7f024e6ef9b47381c8c96c6e1fd3352` |
| `pins.json` production cpu rows / permutations / instructions | 2 047 268 / 54 515 / 2 057 401 | 893 606 / 54 515 / 903 739 |
| `pins.json` aggregate test N=1/2/3 cpu rows (tier) | 462 262 (19) / 924 115 (20) / 1 385 968 (21) | 231 224 (18) / 462 039 (19) / 692 854 (20) |
| `LOOP_OVERHEAD` (test and production alike) | 274 | 274 |
| production N=1 aggregate, cpu rows (tier) | 2 047 542 (21) | 893 880 (20; 154 695 under `2^20`) |
| production N=2 aggregate (`production_n2_aggregate_emulates_within_bounds`) | 4 094 675 (22) | 1 787 351 (21; 309 800 under `2^21`) |
| production N=3 aggregate (`production_n3_aggregate_emulates_within_bounds`) | 6 141 808 (23) | 2 680 822 (22) |
| production N=4 aggregate (one-off emulation, docs/04) | 8 188 941 (23) | 3 574 293 (22; 620 010 under `2^22`) |

The production N=2/N=3 emulations stay inside the bounds (max address 4 540 120; top timestamps
28 597 631 and 42 893 167, under `2^27`). The machine class per rung is docs/04's derivation from
the measured live-heap terms — production N=1 ≈ 190–240 GB (a 256 GB host), N=2 ≈ 475 GB, N=4
≈ 950 GB — projections until the tier-20 production proof runs. The fullnode re-vendors and
re-pins `admitted_shapes[].aggregate_program_digest` at the next chain cut; no running chain has
aggregation enabled.

## Phase 3: the fold and the reduction in the reduce chip (2026-10-05)

Cut D (the reduction's layout preprocessed: one `REDUCE` row per layout entry, chains carried in
the chip), Cut E1 (the committed row hinted whole, its own slot checked by one register-addressed
`LOADE`; the tape's `CommitPhaseOpenings` carries `2·a` words a round, was `2·(a − 1)`), Cut E2
(`FOLD`, opcode 28) and Cut F (`POW`, opcode 29) — the record, the bands, the per-cut span tables
and the live heap are `docs/06-phase3-fold-reduce.md`. The interface `[vk ‖ N ‖ B(8) ‖ 35·N]`,
the binding, `verify_aggregate`'s API, the `inner_vk_digest` (`346ee184…5fb9`) and the admission
stub's list and digest do **not** move; the program does, and so does its key (the reduce chip's
preprocessed region: the layout, and the 14-row fold coefficient table).

| pin | phase 2 | phase 3 |
|---|---|---|
| `aggregate_program_digest`, production bundle shape (what a chain's aggregation section pins) | `c90b3f0a7758c7e306042f27a94cc1f123441b0284c7352cb3f426048c7a74d8` | `dc350ecf6b60af74f4bb032bdf607c3fa0fbd6317705f0b1077e71b455e38ba0` |
| `aggregate_program_digest`, test fixture shape (`tests/verifier.rs`) | `5f1f69010b8aa4cbb6072ffd8a631fa05897c18ed3663ae2bcd136455d2612df` | `df3a18b8d3294a591a2e8fd79f5430550cd9f09afcff6fc8aea89cc1bfaf1073` |
| single-proof program, production (`src/programs/verify_rv32.digest`) | `723218da65a50f1f1581013f79fa5c5b1816b7ab46796dbaa4672c52bce2d0d1` | `cf5a350a62fa00bb6e84fa0de311a726aac7c610d23ce272b8c80795bac51788` |
| Off replay, production shape (`tests/verifier.rs`) | `39bb6b8d94e62dd282001384d0b65294e7f024e6ef9b47381c8c96c6e1fd3352` | `c580415bdaccf7888e7602e793198874e39e0bda8951d11ef6e47ed029455e6c` |
| `pins.json` production cpu rows / permutations / instructions | 893 606 / 54 515 / 903 739 | 585 686 / 54 515 / 597 259 |
| `pins.json` aggregate test N=1/2/3 cpu rows (tier) | 231 224 (18) / 462 039 (19) / 692 854 (20) | 169 640 (18) / 338 871 (19) / 508 102 (19) |
| `pins.json` aggregate test N=1/2/3 mem accesses | 504 514 / 1 008 354 / 1 512 194 | 442 594 / 884 514 / 1 326 434 |
| `LOOP_OVERHEAD` (test and production alike) | 274 | 274 |
| production N=1 aggregate, cpu rows (tier) | 893 880 (20) | 585 960 (20; 462 615 under `2^20`) |
| production N=2 aggregate (`production_n2_aggregate_emulates_within_bounds`) | 1 787 351 (21) | 1 171 511 (21; 925 640 under `2^21`) |
| production N=3 aggregate (`production_n3_aggregate_emulates_within_bounds`) | 2 680 822 (22) | **1 757 062 (21; 340 089 under `2^21`)** |
| production N=4 aggregate (one-off emulation, docs/06) | 3 574 293 (22) | 2 342 613 (22; 1 851 690 under `2^22`) |

Every production number is an emulation over cached production fixtures on this tree
(`build_traces` over the real executions, no proving; N=4 a one-off run for this record).
Derivation check, as docs/04 did it: the per-proof body is (1 757 062 − 585 960) / 2 = 585 551,
so N=2 = 585 960 + 585 551 = 1 171 511 and N=4 = 1 757 062 + 585 551 = 2 342 613 — both exactly
what the emulations measured. The production N=3 aggregate now fits tier 21 (it needed 22), and
the test N=3 aggregate tier 19 (it needed 20). The production N=2/N=3 emulations stay inside the
bounds: max address 4 438 040 (was 4 540 120); top timestamps 18 744 191 and 28 113 007, under
`2^27`; 109 004 and 163 491 permutations, 3 806 786 and 5 709 842 RAM accesses.

### The N-economics at the phase-3 tiers

Declared log-heights from `build_traces` (cpu / reg / ram / poseidon2 / reduce / program; public
`2^3`, range `2^8`). The memory column is a projection: docs/04's cell model — each instance
weighted by its committed cells, `height × (width + 4 salts)` for the main trace plus
`height × (2·chunks + 4)` for its one quotient matrix (docs/05's layout) — scaled from the
measured tier-18 twin (26.88 GB live, the test N=1 shape, docs/06 §3); the production column's
upper figure is docs/05's own production projection scaled by the same cells (docs/06 §3 has the
derivation and the model's ±10 % calibration):

| N | profile | tier | cpu rows | headroom under the tier | declared log-heights | memory (projected; N=1 test measured) |
|---:|---|---:|---:|---:|---|---|
| 1 | test | 18 | 169 640 | 92 503 | 18 / 19 / 19 / 14 / 16 / 18 | **26.88 GB measured** (the twin) |
| 2 | test | 19 | 338 871 | 185 416 | 19 / 20 / 20 / 15 / 17 / 18 | ≈ 52 GB |
| 3 | test | 19 | 508 102 | 16 185 | 19 / 21 / 21 / 16 / 17 / 18 | ≈ 78 GB |
| 1 | production | **20** | 585 960 | 462 615 | 20 / 21 / 21 / 16 / 18 / 20 | ≈ 110–130 GB |
| 2 | production | **21** | 1 171 511 | 925 640 | 21 / 22 / 22 / 17 / 19 / 20 | ≈ 210–245 GB |
| 3 | production | **21** | 1 757 062 | 340 089 | 21 / 22 / 23 / 18 / 20 / 20 | ≈ 290–340 GB |
| 4 | production | **22** | 2 342 613 | 1 851 690 | 22 / 23 / 23 / 18 / 20 / 20 | ≈ 410–490 GB |

Tier 22 now holds up to N=7 (4 099 266 rows) and tier 23, the top rung, up to N=14 (8 198 123)
by cpu rows — **but the reduce chip caps what verifies first**: 196 480 reduce rows a production
proof against `REDUCE_MAX_LOG_HEIGHT = 20` admit **production N ≤ 5** (canonical reduce heights
`2^18` / `2^19` / `2^20` at N = 1 / 2 / 3–5), and 39 296 a test proof admit **test N ≤ 26**
(docs/06 §3, the final fix wave). Production N=6 and N=7 fit tier 22's cpu rows and have no
verifiable reduce height; `prove` and `aggregate` refuse them before any trace or tape
(`ProveError::ReduceRows`, `AggregateError::TooManyProofs`), and `verify` refuses any reduce height
but the canonical one for the program and N (docs/06 §5) — the constant is not raised in phase 3.
At equal N the production rungs are where phase 2 left them except N=3, one lower; what phase 3
bought is memory-table height — the register table one height shorter at every production N and at test N=1 and 2 (test N=3
stays at `2^21`), the RAM table one height shorter at production N=1, 2 and 4 (production N=3 stays
at `2^23`) and at no test N (docs/04's tables against the heights above) — and with it
roughly half the projected memory of phase 2's figures (≈ 240 / 475 / 950 GB at N=1 / 2 / 4).
The test-profile N=2 and N=3 aggregates do not fit this 48 GB box by the model (≈ 52 and
≈ 78 GB); the N=1 shape does, measured (docs/06 §6).

## Constraint set 8, proved: the 512 GB run for fullnode #45 (2026-09-30)

Every deferred rVM proof of the runbook (`docs/03`, rows 3–7) ran on one machine — a 64-vCPU
AMD EPYC 9555P, 503 GB, no swap, Ubuntu 24.04 — on `feat/issue-45` (`aeacf31`, the tree
fullnode v0.6.7 vendors, plus test-only commits), `cargo test --release`, one process per proof
(the prover is single-threaded; proofs ran side by side under a memory budget, so the walls are
uncontended for CPU but not for memory bandwidth). Peaks are `/usr/bin/time -v`'s maximum
resident set of the test binary. Fixture cache: 13 test + 50 production bundle proofs in 238 s
wall, 63 processes at once, ~232 s of CPU each, 5.7 GB per process.

| run | tier | cpu rows | prove | verify | proof size | peak RSS |
|---|---:|---:|---:|---:|---:|---:|
| N=1 test aggregate round trip, in suite (`a_one_proof_aggregate_round_trips…`) | 19 | 462 262 | 2 034.6 s for the test binary (prove + verify + five tampered variants) | — | 334 778 B | **94.5 GB** |
| exit twin: the single-proof program over one test proof | 19 | 461 988 | 2 001.8 s | 24.71 s | 335 003 B | 94.2 GB |
| N=2 test aggregate (`two_test_profile`) | 20 | 924 115 | 3 983.5 s for the test binary | — | 355 577 B | **183.7 GB** |
| N=3 test twin (`twin`) | 21 | 1 385 968 | 4 807.8 s | 24.75 s | 347 800 B | **221.0 GB** |
| M5.2 production exit: the single-proof program over one production proof | 21 | 2 047 268 | 8 164.8 s | 99.31 s | 1 566 619 B | **376.9 GB** |
| production N=1 aggregate (`production_n1_aggregate_proves_and_verifies`) | 21 | 2 047 542 | 8 131.3 s | 99.36 s | 1 563 226 B | 376.9 GB |
| production N=2 aggregate (tier 22) | 22 | 4 094 675 | not attempted: the production tier-21 peak (376.9 GB, twice) scales to ~750 GB at tier 22 (every table one height taller), above the 503 GB box |
| production N=3 aggregate (tier 23) | 23 | 6 141 808 | not attempted: the tier-22 run above already exceeds the box |

**The memory finding.** Every measured peak is a multiple of what this document and `docs/01`
derived: the tier-19 test aggregate takes 94.5 GB where the M5.3 exit table recorded 30 GB
(cs6, macOS, watchdog-sampled) and the production exit takes 376.9 GB where `docs/01` derived a
48.6 GB committed oracle and a 43–61 GB peak. The peaks scale by ~1.95× from tier 19 to 20 and
~1.2× from 20 to 21 at the test profile, and the production shape at tier 21 costs 1.7× the
test shape's (its memory tables are two heights taller). A tier-22 production aggregate
therefore needs on the order of 700–800 GB and tier 23 more than a terabyte: **the ≥ 128 GB /
≥ 160 GB host classes this document and `docs/03` name for production N=2/N=3 are wrong by
about 5×**; the rung a CPU box can reach is the production N=1 at tier 21 (≥ 512 GB). The
mismatch is between the 2026-09-15 oracle model and the prover as it stands (constraint sets 7
and 8 widened every table and the model was never re-calibrated), not a leak: the exit at tier
21 holds its peak through the commit phase and frees it before FRI. (2026-10-03: the live-heap
profile of the tier-19 shape — 78.7 GB live when killed, four terms of which the committed main
trace is one — is `docs/04-phase2-row-cuts.md` §"The prover's live heap"; the macOS figures this
document quotes from September are RSS, which on macOS excludes compressed and swapped pages.)

**Tier 22's headroom is 2.4 %.** The production N=2 program runs 4 094 675 rows against tier
22's 4 194 303 (`production_n2_aggregate_emulates_within_bounds`); one more column-set in the
inner AIR of the size constraint set 7 added (+75 887 rows a proof) would push N=2 to tier 23.

**The #62 review's gap, closed (`tests/aggregate.rs`, the B3 vehicles).** The production N=2
and N=3 aggregate programs execute in the emulator over real production proofs — 4 094 675 rows
(tier 22, 109 004 permutations, 5 703 450 memory accesses, 421 535 tape words) and 6 141 808
rows (tier 23, 163 491, 8 554 838, 632 298) — publishing the host's bound interface digest;
the highest address touched is 4 664 040 for both N (the spill arena is reused per iteration, so
the 80 unrolled queries' register pressure does not grow with N), and the top timestamp
(65 514 815 and 98 268 943) is inside the 2^27 collision-free window. Emulation only; 11 s each.

**The production-profile constraint differential and the non-first-instance break
(`tests/verifier.rs`).** The emitted constraint DAG folds to the same accumulator, quotient and
four Lagrange selectors as p3-batch-stark's own folder on all nine instances at 80 queries
(`the_emitted_constraint_evaluation_equals_the_native_folder_at_production`), and one opened
trace value of each non-first instance moved in turn traps at that instance's own
`quotient identity[i]` (`breaking_one_air_constraint_on_a_non_first_instance_is_refused_at_that_instances_step`).

**The forged-aggregate exercise (`tests/cheating.rs`, fullnode #45).** Two legs against the
fixed rVM. (1) A real bundle proof with one published word moved no longer verifies natively
and cannot be aggregated: `aggregate` refuses it at the tape replay, before any rVM work
(`a_malicious_inner_proof_cannot_be_aggregated`). (2) Inside the real N=1 aggregate verifier's
execution (462 262 events over one real inner proof), the stored high lane of the first
register-allocator spill (STOREE event 963) is rewritten to `0xC0FFEE` the way RVM-1 describes,
and the rVM proof is built two ways past every host check — with the pre-fix register table (no
read of `rd + 1`) and with the fixed table carrying the forged read; both are refused by
`Machine::verify` at tier 19 (`a_forged_stored_high_lane_in_the_aggregate_verifier_is_refused`,
58:46 for the two proves, 95.5 GB). **The red-first run, RVM-1's fix alone reverted** (in a scratch copy, `EXT_READ_RD` emptied, never
committed): the toy vectors go red — the forged run *verifies*, publishing
`[12648430, 11, 11, 22]` — so the committed refusals have teeth. The aggregate-scale test stays
green on the reverted rVM, and its teeth are the RAM table's read-after-write, not RVM-1 (the
forge rewrites the stored lane but the spill's reload still reads the honest value). Letting the
program carry the forged lane forward instead, at 41 of the run's 14 788 STOREE rows, traps every
time in the verifier's own checks (`commit phase root[*]` 32 times, `quotient identity[*]` 5,
`sample_bits decomposition` 3, `lookup terminal sum` 2). A random lane is caught by the arithmetic
that consumes it; a lane *chosen* to cancel a failing check — the recursion-VM report's §6 path —
was not constructed, so nothing here claims the unfixed rVM was unforgeable at this scale. That
choice is what the fix removes, and the toy vectors are its red.

## ZKQ-5: the self-verifier's binding against the inner aggregate's (decided 2026-09-28)

The finding: `rv32r` hints its own eight binding words `B_out` and absorbs them into
`[rvm_vk ‖ 1 ‖ B_out ‖ 4]`, but nothing in the program ties `B_out` to the binding `B_in` the
inner aggregate absorbed. Asked: must the program assert `B_out == B_in`?

**Decision: no in-program equality; the tie is the verifier's recompute, and that is a rule.**

- The program *cannot* see `B_in`. The inner proof's four public values are its interface digest
  `D_in = H(vk_in ‖ N ‖ B_in ‖ 35·N)`; `B_in` exists inside the self-verifier only as a
  preimage word of a Poseidon2 digest. Asserting equality means hinting the whole inner preimage
  (`13 + 35·N` words), re-sponging it to `D_in` in-program and comparing — a variable-length
  interface for what is today a fixed four-word one, and a second copy of the `rv32n` phase-8
  schedule inside `rv32r`. Not small, and not needed:
- The chain never takes `D_in` on a prover's word. `verify_aggregate`'s pattern (binding check,
  then digest recompute, then `Machine::verify`) applied to a tree recomputes every level from
  the covered bundles' public values and the chain's *one* `B` (the transaction's
  `H("rand-aggregate-bind-1", chain_id ‖ aggregator ‖ nonce)`): `D_in' = H(vk_in ‖ N ‖ B ‖ pvs)`,
  then `D_out' = H(rvm_vk ‖ 1 ‖ B ‖ D_in')`, compared with the outer proof's public values.
  Poseidon2's collision resistance then forces `B_out = B` and `B_in = B` — so `B_out = B_in` —
  exactly as the one-level `BindingMismatch`/`DigestMismatch` pair forces it for `rv32n`. A
  re-wrapped victim aggregate (inner proved under the victim's `B_v`, outer under the thief's `B`)
  fails at `D_in' ≠ D_in`.
- A verifier that accepted `D_in` as opaque would be broken with or without the equality: it
  would accept an outer proof over *any* inner statement. So the load-bearing rule is the
  recompute, and the in-program equality would add nothing a correct verifier does not have.

**The rule for whoever registers a tree, as implemented** (tree aggregation, `docs/08` §4 and
§6): a tree aggregate is verified by `aggregate::verify_tree`, which recomputes each level's
interface digest bottom-up from the covered bundles' public values (in cover order) and the
chain's own binding, the same `B` at every level, under the per-level key list (`vk_leaf` for the
leaves, then `step_keys`, the last entry repeating), and compares the result with the root's four
public values before `verify_n(root program, root, 2)`. It never compares only the root's words.
The fullnode's admission calls it at step 8 (`docs/aggregation.md` §3.8). If a future design needs
an outer proof whose inner digest the chain cannot recompute (an inner proof over data the chain
does not hold), revisit this: that design must open `D_in` in-program and assert `B_in == B_out`.

## The N-economics, measured (test profile)

(Constraint set 6, 2026-09-15 — the record of the row model. Current: N=1/2/3 = 169 640 /
338 871 / 508 102 rows at tiers 18 / 19 / 19, "Phase 3" above; 231 224 / 462 039 / 692 854 at
18 / 19 / 20 after phase 2.)

The shipped program (`Checkpoints::Off`, liveness and precompiles on) over the fixture shape;
the tape is `1 + 43 344·N` words exactly. The program itself is 443 893 instructions — once,
independent of `N`.

| N | tier | cpu rows | permutations | mem accesses | witness words |
|---:|---:|---:|---:|---:|---:|
| 1 | 19 | 441 782 | 11 205 | 597 043 | 43 345 |
| 2 | 20 | 883 240 | 22 382 | 1 193 489 | 86 689 |
| 3 | 21 | 1 324 694 | 33 558 | 1 789 918 | 130 033 |

The row model, measured and closed: `rows(N) = 328 + N · 441 454 + 4·⌊N/2⌋`. The 328 is the
preamble and post-loop (the count word and its guard, the interface sponge's state, the vk
digest absorb, the final partial-block permutation, the four published words); the 441 454 is
the per-proof body — the single-proof program's 441 643 rows with its phase-8 list build and
one-shot `sponge_seeded` *replaced* by the 34-word staged absorb, 189 rows cheaper per proof;
and the parity term is the absorb's rate-fill schedule: the fill phase advances two lanes per
proof (34 mod 4), so every odd iteration permutes nine times where an even one permutes eight,
at four rows the difference (the permutation row, the absolute-address fold, the two rewind
rows). The N=1 pin equals the single-proof rows plus the 139-row loop overhead, and the budget
test asserts the two pins agree exactly — the loop's cost is a measured number, not a guess.

The permutation model: `perms(N) = 29 + 11 176·N + ⌊N/2⌋` — the interface digest costs the same
permutations as the single-proof program's phase 8 did (the absorb schedule *is* the same
sponge), so the per-proof count is the single-proof's 11 205 minus the 29 the preamble pays
once.

## The N-economics, derived (production)

(Constraint set 6, 2026-09-15. Current: N=1 at tier 20, N=2 and N=3 at 21, N=4 at 22, all
emulated — "Phase 3" above (phase 2 had N=3 at 22); the oracle-memory column below is the
withdrawn model.)

The production inner proof's rows are M5.2's pin (1 968 619 rows, 51 605 permutations); the
per-N scaling is the measured test-profile law applied to the same structure. The loop overhead
at the production shape is **measured**, not assumed: 1 968 758 rows for the production N=1
aggregate — the pin plus the same 139 rows (`the_production_n1_aggregate_is_the_m52_pin_plus_loop_overhead`,
which also re-asserts the M5.2 pin itself):

| N | tier | cpu rows | oracle memory | machine class |
|---:|---:|---:|---:|---|
| 1 | 21 | 1 968 758 (measured) | 48.6 GB (M5.2's measured derivation) | ≥ 64 GB |
| 2 | 22 | ~3.94 M (derived: 2× the N=1 body, plus the preamble) | ~95.3 GB | ≥ 128 GB |
| 3 | 23 — **no such rung** | ~5.91 M (same derivation) | ~127 GB | ≥ 160 GB |

`TIERS` stops at 22 (`01-rvm-machine.md`): a production N=3 aggregate returns
`Tier::for_cycles == None` — unprovable anywhere, by construction, and N=2 needs a 128 GB
machine. The production N≥2 aggregates are therefore *written, not executed here* (R4): per the
2026-09-15 ruling they will be executed on a ≥64 GB machine after chain-side aggregation lands,
and M5.4's GPU backend is the path beyond that (the tier-23 rung exists nowhere until the GPU
memory model is measured). The M5.3 exit is the test-profile N=3 twin below, at the same
*structure* of work the production N=1 has.

## The exit, measured

The exit (spec §7, R4's profile ruling): an aggregate of **three real test-profile bundle
proofs** proves and verifies natively. What this box admitted on 2026-09-15, and the plan's
fallback applied honestly:

| run | prove | verify | proof size | peak RSS |
|---|---:|---:|---:|---:|
| N=1, tier 19 (round-trip) | three completed runs: ~30 min wall contended (the full suite alongside), then 1 614 s and 1 578 s for the whole test binary on the quieter box (the M5.2 anchor for the same shape is 1 707.7 s) | not split out this run (M5.2's 18.31 s key-build anchor applies at the same 2^19) | **328 121 bytes** (M5.2's single-proof twin: 327 321 — the aggregate's declared heights carry the loop's small overhead) | 30 GB (watchdog-sampled) |
| N=2, tier 20 | **jetsam'd twice** (SIGKILL), reaching 33.7 GB and 33.3 GB sampled — above this box's practical line (~33 GB today) | — | — | 33.7 GB before the kill |
| N=3, tier 21 (the twin) | **jetsam'd** (SIGKILL) ~55 s into the prove, reaching 31.5 GB sampled — the box's line moved down as pressure spiked; the tier-21 prove never entered its NTT phases | — | — | 31.5 GB before the kill |

The plan's fallback clause: *if the heavy run dies to contention, record the heaviest completed
run as the in-scope proof and the rest as deferred with the measured peak reached*. The
completed in-scope proof is the **N=1 tier-19 aggregate** (the round-trip test: proves,
verifies, returns the bundle's `OUT0..7`, and both tampered variants are refused); N=2 and N=3
are proven *structurally* — the N=2/N=3 emulations accept and publish the host's §4.4 digest
(`n3_aggregate_publishes_the_host_interface_digest`, in-suite) and their rows are pinned in
`tests/pins.json` — and deferred as native proofs with the peaks above. **The 2026-09-15
ruling on every deferred run:** the heavy proofs — the test-profile N=2/N=3 twins here and the
production-profile ones (M5.2's tier-21 exit, the production N≥2 aggregates below) — are
*written* now, and they will be *executed on a ≥64 GB machine after chain-side aggregation
lands*. That is a scheduled run, not "as soon as hardware allows": the M5.2 era already
completed a tier-21 rVM proof on this machine class under a 42 GiB watchdog, so the line is
contention, not structure. The two `#[ignore]`d tests (`two_test_profile_…`, `twin_three_…`)
carry the watchdog command lines.

## The API

`recursion/src/aggregate.rs` — spec §6, amended by M5.2's R5/R6 and M5.3's R6:

- `InnerProof = rand_zkvm::machine::Proof` — the 35 public values (cs8: `GAS` last) ride inside it; the empty
  public segment's `H_PUB` is a prover-computed constant of the shape.
- `InnerVerifierKey { shape, key }` — what an aggregate proves under: one inner shape and its
  preprocessed cap.
- `aggregate_program(vk) -> Program` and `aggregate_program_digest(shape, key) -> [F; 4]` — the
  registered artifact and its name: the N-generic program, built once, pinned by digest.
- `aggregate(m, vk, proofs, binding, tier) -> Result<AggregateProof, AggregateError>` — refuses the
  empty set (`Empty`), shape-checks every inner proof before any tape work
  (`WrongShape { index }`), builds the N-proof tape (`Tape`), proves (`Prove`), and asserts the
  executed program's published digest equals the host-computed one at prove time
  (`DigestMismatch`, R6). Returns the proof and its §4.4 list.
- Tree aggregation (`docs/08`): `TreeKeys { vk_leaf, step_keys }` and
  `TreeShapes { leaf, steps }` (per-level lists, the last entry repeating at a fixed point);
  `tree_root_digest` (the host recompute), `verify_tree(m, root_program, proof, inner, covered,
  binding, leaf_size, depth, keys)` (recompute, compare, then `verify_n(…, 2)`),
  `prove_tree_step(m, child, [&Proof; 2], binding, tier)` and `aggregate_tree(m, inner, &TreeShapes,
  proofs, binding, leaf_size) -> (Proof, depth)`.
- `verify_aggregate(m, program, a, binding) -> Result<Vec<[u32; 8]>, VerifyAggregateError>` —
  refuses a list whose eight binding words are not the caller's `binding` (`BindingMismatch`,
  AGG-2), then recomputes the §4.4 digest from `a.public` and compares it against the proof's batch public values
  (`DigestMismatch` — the `verify_public` pattern), then runs the ordinary rVM
  `Machine::verify` (`Verify`), and returns each covered bundle's `OUT0..7` in proof order.

The derive lists the plan sketched narrow to what compiles: `AggregateError` and
`VerifyAggregateError` are `Debug`-only (`ProveError`/`VerifyError` have no `Clone`/`PartialEq`),
and `AggregateProof` has no derives at all (`BatchProof` has neither trait) — a second handle
is a `to_bytes` round-trip, the fixture cache's own move.

## Startup: the key-build story

The fullnode builds the N-generic program once at startup and registers its digest. The program
*build* (DSL emission plus the allocator's replay, 443 893 instructions) measures seconds; it is
not the cost. The cost is the verifier key — the preprocessed commitment over the program table
— built lazily per `(tier, program digest, reduce)` triple by the machine's 64-entry FIFO
`KeyCache` (`src/machine.rs`), so a node pays it on the first verification of a given tier and
never again while the entry lives. The measured anchor is M5.2's twin: 18.31 s for the 2^19
test-profile build, key-build-dominated. The 2^21 production build is estimated at ~30–70 s
(same construction, four times the program-table rows; the measurement is the ignored
production test's business, not the suite's).

## What the chain must carry (R5's two corrections)

Both flow from the interface digest binding *one* shape, not from preference:

1. **Sealed history must carry each covered bundle's declared shape** — `tier` plus the six
   declared log-heights (`program`, `input`, `keccak`, `sha256`, `public`, `mem`), the 9 bytes
   per bundle the plan sizes it at. Without them the admission stub cannot reconstruct the
   shape, and `Machine::verify` would refuse the aggregate only *after* the rVM work.
2. **Admission must shape-check every covered bundle** against the aggregate's registered
   shape. The program's per-iteration header asserts already pin every proof to the shape at
   prove time, so a mixed-shape set cannot *prove*; the admission check is the cheap refusal
   that keeps such a transaction out of the mempool before any rVM work.

## The fullnode admission stub (spec only — implemented by a fullnode session)

A new, small fullnode-side function; no rVM vendoring in M5.3. Exactly:

1. Input: an aggregate transaction (`Aggregate { covers, proof, payout, r }`), the covered
   bundles' records, and the node's registered aggregate-program digest.
2. For every covered bundle: read its declared shape (`tier` plus the six declared log-heights
   — correction 1), and check it equals the aggregate's shape (correction 2).
3. Compute the `InnerShape`-equivalent words from the shape (the `shape_words` layout in
   `recursion/src/shape.rs`), the inner cap from
   `Machine::verifier_key(tier, the six heights)`, then
   `inner_vk_digest = PaddingFreeSponge<Perm, 8, 4, 4>` over
   `[RVM_VK_DOMAIN = 16 ‖ shape words ‖ cap(16)]`.
4. Compute the transaction's binding `B = H("rand-aggregate-bind-1", chain_id ‖ aggregator ‖
   nonce)` as eight `u32` words (`aggregate_binding` in `randprotocol-core`; AGG-2). The node
   derives it from the transaction it is admitting — never from the words the proof's list
   carries.
   Build the interface list `[inner_vk_digest(4) ‖ covers.len() ‖ B(8) ‖ per bundle its 35 pv in
   cover order]`, and `public_digest` over it: state `[0,0,0,0, RVM_PUB_DOMAIN = 17, len, 0, 0]`,
   then one permutation per four words overwriting rate lanes 0..4 (a partial trailing block
   overwrites only its own lanes), digest = lanes 0..4.
5. Compare the four words with the aggregate proof's batch public values; mismatch → the
   aggregate is invalid. Then the ordinary rVM `Machine::verify(&registered_program, proof)`.

**Test vectors** (the 3-proof test-profile fixture set; hex is each word's canonical `u64` as
16 lowercase hex chars, concatenated in lane order — reproduced by
`cargo test --release -p recursion --test aggregate the_admission_stub_vectors -- --nocapture`):

- `inner_vk_digest` (a deterministic constant of the fixture shape — the bundle program, input
  sizes and tier are data-independent, so a regenerated fixture cache reproduces it; pinned in
  the test; constraint set 8 moved it with the inner machine — the constraint-set-7 value was
  `ee072b7a8eb766c7de6fb4fffa1f9f1b6098c8971b1b49eec2f4e0091edadfbe`, the constraint-set-6 one
  `33a94ec690bb7cbe5a3d4564967460996277ac61b539f6525b5fe7f92992a1c8`):
  `346ee1841980e46a3501f5b04cdf40dd3208e5b1c67360285353cf7a0b735fb9`
- the binding (AGG-2), the tests' fixed stand-in `common::TEST_BINDING` — on a chain it is the
  transaction's `H("rand-aggregate-bind-1", chain_id ‖ aggregator ‖ nonce)`:
  `00000000a662000000000000a662000100000000a662000200000000a662000300000000a662000400000000a662000500000000a662000600000000a6620007`
- the interface list, 118 words: `[vk(4) ‖ 3 ‖ B(8) ‖ 35·3]`. The fixture notes are random per
  cache (this is the constraint-set-8 cache as regenerated for the final review's `gas_max`,
  2026-09-29 on the 48 GB laptop — 13 test-profile proofs at ~105–135 s each, four processes,
  ~2 GB each; the first cs8 cache's list digested to
  `36b414c0205da8dc6653f2e12f34596ece718d4ef22c1b947012582e55dcf5dd`), so the list rides on
  this checkout's fixtures; its *shape* is pinned — word 4 is `3` (the count), words 5–12 are
  the binding, words 13, 48, 83 are `0` (each proof's `PC_ENTRY`), words 14, 49, 84 are `14`
  (every proof's `TIER`), words 47, 82, 117 are `20479` (each proof's `GAS`, cs8's 35th value —
  the default declared limit, `gas::gas_max` of the tier-14 hash-free header,
  `(2^14 − 1) + 2^12`; `16383` before the final review added the absorb rows' term), each proof's `HC0..7` run repeats
  across the three (same bundle program) while its `IN0..7` run differs (different inputs), and
  its `PUB0..7` run repeats (the empty public segment's `H_PUB`, a constant of the shape). As
  measured on this checkout:

  ```
  346ee1841980e46a3501f5b04cdf40dd3208e5b1c67360285353cf7a0b735fb9000000000000000300000000a662000000000000a662000100000000a662000200000000a662000300000000a662000400000000a662000500000000a662000600000000a66200070000000000000000000000000000000e00000000fcf4c2ca00000000a634a055000000009279293b00000000ee8d851600000000c5717852000000006d0561ed000000008dd81da70000000018e0b601000000006f35274a000000000371953700000000a8a42560000000004b291c6600000000b7c2de0e00000000d6bf7fcf00000000182b470b00000000fb4abd6c000000007bbf5012000000006c808b59000000006aea0597000000002d75974e00000000b566bfb900000000aba9b10300000000c8df477b00000000bf85ec8f00000000934a275900000000d5389ac8000000002e612784000000008639ed090000000085f58a21000000004448d889000000006bb9c915000000000671dc2c0000000000004fff0000000000000000000000000000000e00000000436464ca00000000167c06a600000000528b45b200000000474c4ebf00000000aba47cca00000000d89d7ea300000000e4cf09c4000000006dbb25fc000000006f35274a000000000371953700000000a8a42560000000004b291c6600000000b7c2de0e00000000d6bf7fcf00000000182b470b00000000fb4abd6c000000007d2198900000000032ef87b1000000005cbf60c5000000005369151400000000f796dfdc000000006d341cea00000000ee65f7c10000000083ad87a500000000934a275900000000d5389ac8000000002e612784000000008639ed090000000085f58a21000000004448d889000000006bb9c915000000000671dc2c0000000000004fff0000000000000000000000000000000e00000000d5e68c3200000000b1bfa0e60000000054a9fa70000000006db05c83000000008c8a8cfc000000007d9a619100000000834acb6300000000b4292759000000006f35274a000000000371953700000000a8a42560000000004b291c6600000000b7c2de0e00000000d6bf7fcf00000000182b470b00000000fb4abd6c0000000073dc4e1e00000000bf53608900000000ccde09690000000022e6fe7a00000000ac6bcac10000000078ea8c8c0000000018e98906000000005840b1cf00000000934a275900000000d5389ac8000000002e612784000000008639ed090000000085f58a21000000004448d889000000006bb9c915000000000671dc2c0000000000004fff
  ```
- the interface digest for the list above:
  `5e3d7fb2bd1f5342e49577650a281996b656d1fa4e8f3eff7ee82adefe9d1ed6`
- the program the stub registers, `aggregate_program_digest` at the fixture (test) shape —
  phase 2's row cuts (2026-10-03) moved it from constraint set 8's
  `9eba73805fa23361708d9ca1c58d904ac830aeb6810470ec7788c4f36880193d` to
  `5f1f69010b8aa4cbb6072ffd8a631fa05897c18ed3663ae2bcd136455d2612df`, and phase 3 (2026-10-05)
  to `df3a18b8d3294a591a2e8fd79f5430550cd9f09afcff6fc8aea89cc1bfaf1073` (pinned in
  `tests/verifier.rs`); at the production bundle shape `1831f036…ddd7` →
  `c90b3f0a7758c7e306042f27a94cc1f123441b0284c7352cb3f426048c7a74d8` →
  `dc350ecf6b60af74f4bb032bdf607c3fa0fbd6317705f0b1077e71b455e38ba0`. The vk digest, the list
  and its digest above do not move with it (`the_admission_stub_vectors` passes unchanged).

The fullnode session's stub must reproduce all three byte-for-byte before it is trusted with
admission: the vk digest against the pinned constant, the list and digest against the recursion
crate's printout on the shared cache.

## What M5.3 hands to M5.4

- **The pinned aggregate program and its digest** — one N-generic program per inner shape, the
  registered artifact the fullnode pins by digest; M5.4's self-verifier program reads it the
  way the aggregate program reads the RV32 machine's shape.
- **The measured N-economics** — (2026-10-03: one tier lower since phase 2, and the oracle
  figures in this bullet are the withdrawn model — "Phase 2" above and docs/04) — the tables
  above: production N=1 at tier 21 (48.6 GB oracle,
  ≥ 64 GB), N=2 at tier 22 (~95 GB, ≥ 128 GB), N=3 at tier 23 (~127 GB, ≥ 160 GB, a rung that
  exists nowhere), and the test-profile N=1..3 measured rows calibrating the linear scaling.
  The production proofs are written; their execution is scheduled for a ≥64 GB machine after
  chain-side aggregation lands (the 2026-09-15 ruling), and the GPU backend's first target is
  the production N=2/N=3 aggregate beyond that, with the tier-23 rung added when the GPU memory
  model is measured.
- **The chain-facing API, settled** — `aggregate` / `verify_aggregate` /
  `aggregate_program_digest`, with the startup key-build story measured (18.31 s at 2^19; the
  2^21 production build estimated at ~30–70 s).
- **The chain-side corrections** — sealed history carries each covered bundle's declared shape;
  admission shape-checks every covered bundle. Both stated above as requirements, not
  suggestions.
- **The `H_IN` answer** (R3) — no extra binding; `H_IN` is already bound through `pv::IN0..7`
  in the interface list.
- **The spec amendment to report, not silently edit** — §7's M5.4 line ("its end-to-end proof
  if it fits the laptop, else deferred with the measured requirement") now has the measured
  requirement for the self-recursion input: the N=1 production aggregate at tier 21, 48.6 GB
  oracle, ≥ 64 GB — the same class as M5.2's exit (2026-10-03: history — tier 20 since phase 2,
  and the oracle model is withdrawn; docs/04 has the measured live heap). The tier-23 rung exists nowhere until the
  GPU backend needs it for N=3 (R4).
