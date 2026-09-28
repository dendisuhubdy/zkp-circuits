# 02 — The aggregate program: N bundle proofs in one rVM proof, and what it costs

M5.3 (plan: `docs/superpowers/plans/2026-09-15-zkvm-m5-3.md`; the machine and its single-proof
numbers: `docs/01-rvm-machine.md`). One **N-generic aggregate program per inner shape** (R1):
a counted loop over the tape's `N`, each iteration the single-proof verifier's phases 0–7 over
that proof's tape region with a fresh challenger (R2), then the interface digest over
`[inner_vk_digest ‖ N ‖ B(8) ‖ 34·N]` (R5; the eight binding words B are audit v3's AGG-2
amendment, below). The fullnode registers one program digest per inner shape
(R6); the program covers every `N` the tape holds, because the loop count is a tape value, not a
build-time constant.

Every number below was measured on 2026-09-15 on this machine (macOS, 16 cores, 48 GB) with the
crate's documented command and is pinned by a test where the plan asks for one: the per-N cycle
numbers in `tests/pins.json` (`tests/aggregate.rs::the_per_n_cycle_budget_is_pinned`), the N=1
differential and the tamper table in the same file, the stub vectors in
`the_admission_stub_vectors`. Estimates are labelled with their derivation.

## AGG-2: the aggregate binding (audit v3, amended 2026-09-25)

Before this amendment the interface was `[vk ‖ N ‖ 34·N]` and said nothing about who made the
proof: a registered aggregator could take another's valid aggregate, re-sign the transaction
under its own identity and nonce, and be paid for it. The program now hints eight binding words
straight after `N` and absorbs them into the interface sponge between `N` and the public values,
so the published digest covers `[vk(4) ‖ N ‖ B(8) ‖ 34·N]` with
`B = H("rand-aggregate-bind-1", chain_id ‖ aggregator ‖ nonce)`, derived in `randprotocol-core`.
Eight words are exactly two rate fills, so the absorb schedule after them is the one the count
word alone left, and the unconditional final permutation still holds.

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

## VERIFIER-1: the re-pin (2026-09-28, the chain-16 constraint set, v0.6.1)

The per-proof pipeline (`rv32.rs`'s `emit_proof`, shared by `rv32`, `rv32n` and `rv32r`) now
asserts each FRI commit-phase proof-of-work word is the honest `0` (`docs/00-recursion-vm.md`,
"Segment 7's PoW words"). That adds one `JEQ` and one trap per FRI round to the program, so every
program digest moves; the transcript, the tape and every other cost do not. Cost per verified
proof: +1 cpu row and +2 instructions per FRI round — +8 / +16 at the bundle shape's eight rounds
(test and production alike), +5 / +10 and +9 / +18 at the self-verifier's two fixture shapes.

| pin | before | after |
|---|---|---|
| `aggregate_program_digest`, production bundle shape (what a chain's aggregation section pins) | `e0578970a1981321e044a6bbb947210b79d102daf1083c9b53b752a185709108` | `3e9668067d10f4ea643f2819a95062a75f9e93b75ac50bb5626b77274106388d` |
| `aggregate_program_digest`, test fixture shape (`tests/verifier.rs`) | `1ec0c545003179b1ca4215b439d2d69fa33149a5257a04dc8473030fc2deeeeb` | `ed787251efe213a28d410a068f383dcd75c2caa1c68ee71514ba71b16b4147c6` |
| single-proof program, production (`src/programs/verify_rv32.digest`) | `8901cec9c1681c9674f1e5582805d625c60b20d9f69be546da982622f36e0bda` | `880fe98c92e36671407af7c54952547de6046355dad209650e7e6a18596e5911` |
| single-proof program, test shape | `71f2a93d2033c7c80ed4b5bb7311251eb4c7aa1d9729baa51a8f5f670933b8d8` | `4a0517f841cf14efb69c0206532d0cf554b3cab79e78828884f47703bb3dfc4a` |
| Off replay, production (`tests/verifier.rs`) | `c1c04ac3a9faf266eb8980260dae6c7f12fe9ee4cf3dfa40de8440182258d731` | `bc10a8e1771117d91c8fa30ee11a083404f49280afe4349b816c08c87579fcaf` |
| self-verifier (`self_program_digest`), toy fixture shape (`tests/self_verify.rs`, newly pinned) | `c18fa9eadf161ab625fc23048a6bcd4020eea8eaac33720d34e17f7148cd4804` | `1ebcf3772486f3042f3f7bd29e32a3671c06c4a281135f6230717d73808a90ab` |
| self-verifier cost, toy (rows, perms, mem, instrs, witness) | (276555, 7498, 405853, 278398, 29575) | (276560, 7498, 405853, 278408, 29575) |
| self-verifier cost, busy | (368761, 9132, 481628, 370864, 35407) | (368770, 9132, 481628, 370882, 35407) |
| `pins.json` production cpu rows / instructions | 1 968 619 / 1 978 422 | 1 968 627 / 1 978 438 |
| `pins.json` aggregate test N=1/2/3 cpu rows | 441 862 / 883 320 / 1 324 774 | 441 870 / 883 336 / 1 324 798 |

`inner_vk_digest` (the admission stub vector above) does not move: it is the inner machine's
key, not the program. `LOOP_OVERHEAD` does not move either. The fullnode re-vendors the rVM and
re-pins `aggregate_program_digest` at the chain-16 cut; no live chain carries an aggregation
section, so nothing live moves. **The production proof batch must use this program.**

## The N-economics, measured (test profile)

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

- `InnerProof = rand_zkvm::machine::Proof` — the 34 public values ride inside it; the empty
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
   Build the interface list `[inner_vk_digest(4) ‖ covers.len() ‖ B(8) ‖ per bundle its 34 pv in
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
  the test):
  `33a94ec690bb7cbe5a3d4564967460996277ac61b539f6525b5fe7f92992a1c8`
- the binding (AGG-2), the tests' fixed stand-in `common::TEST_BINDING` — on a chain it is the
  transaction's `H("rand-aggregate-bind-1", chain_id ‖ aggregator ‖ nonce)`:
  `00000000a662000000000000a662000100000000a662000200000000a662000300000000a662000400000000a662000500000000a662000600000000a6620007`
- the interface list, 115 words: `[vk(4) ‖ 3 ‖ B(8) ‖ 34·3]`. The fixture notes are random per cache (this cache regenerated
  2026-09-21 after the original was lost; the vk digest above is unchanged),
  so the list rides on this checkout's fixtures; its *shape* is pinned — word 4 is `3` (the
  count), words 5–12 are the binding, words 13, 47, 81 are `0` (each proof's `PC_ENTRY`), words 14, 48, 82 are `14` (every
  proof's `TIER`), each proof's `HC0..7` run repeats across the three (same bundle program)
  while its `IN0..7` run differs (different inputs), and its `PUB0..7` run repeats (the empty
  public segment's `H_PUB`, a constant of the shape). As measured on this checkout:

  ```
  33a94ec690bb7cbe5a3d4564967460996277ac61b539f6525b5fe7f92992a1c8000000000000000300000000a662000000000000a662000100000000a662000200000000a662000300000000a662000400000000a662000500000000a662000600000000a66200070000000000000000000000000000000e000000000a37f92000000000ac819f8e00000000f82f671d00000000354a3037000000003153f3de000000009a2dcd060000000046a46766000000009d44a4ad000000006f35274a000000000371953700000000a8a42560000000004b291c6600000000b7c2de0e00000000d6bf7fcf00000000182b470b00000000fb4abd6c00000000a26dd43c00000000e9cb3eb300000000ac53ff3d00000000ae693458000000009609b3a0000000008cd378a4000000008ef51ada00000000f65dd77800000000934a275900000000d5389ac8000000002e612784000000008639ed090000000085f58a21000000004448d889000000006bb9c915000000000671dc2c0000000000000000000000000000000e00000000c58f3f9d00000000377d3abb0000000014f687b8000000007f9cd8d900000000a4e0896200000000d61a1017000000008205eec600000000b625bd4c000000006f35274a000000000371953700000000a8a42560000000004b291c6600000000b7c2de0e00000000d6bf7fcf00000000182b470b00000000fb4abd6c00000000edcf535f00000000777cd08d000000006e199e6b00000000fc87f93b00000000002a7d2c0000000051a00288000000000dd4c690000000007c52d05d00000000934a275900000000d5389ac8000000002e612784000000008639ed090000000085f58a21000000004448d889000000006bb9c915000000000671dc2c0000000000000000000000000000000e00000000eac3c4d10000000033df413600000000182f953e00000000bcd17c110000000073f3f13400000000eea424400000000084cd185d000000007f3faedb000000006f35274a000000000371953700000000a8a42560000000004b291c6600000000b7c2de0e00000000d6bf7fcf00000000182b470b00000000fb4abd6c0000000017db673f00000000057e71ce000000005fef925c00000000be76fcf500000000a2288d160000000033bcde4400000000c40acedf00000000e584ded700000000934a275900000000d5389ac8000000002e612784000000008639ed090000000085f58a21000000004448d889000000006bb9c915000000000671dc2c
  ```
- the interface digest for the list above:
  `9833ac5b15e54b7229ed77e1db98919d86f660d06937b980d55c83df6fdc868e`

The fullnode session's stub must reproduce all three byte-for-byte before it is trusted with
admission: the vk digest against the pinned constant, the list and digest against the recursion
crate's printout on the shared cache.

## What M5.3 hands to M5.4

- **The pinned aggregate program and its digest** — one N-generic program per inner shape, the
  registered artifact the fullnode pins by digest; M5.4's self-verifier program reads it the
  way the aggregate program reads the RV32 machine's shape.
- **The measured N-economics** — the tables above: production N=1 at tier 21 (48.6 GB oracle,
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
  oracle, ≥ 64 GB — the same class as M5.2's exit. The tier-23 rung exists nowhere until the
  GPU backend needs it for N=3 (R4).
