# 11 — The next levers after phase 5 (ZKVM-113)

Monorepo issue 66 gathers eight open rVM levers. This page records what was done about each on
`feat/i66-rvm-key-version` and what was not. One item is built (item 2, opt-in); two were
measured at a smaller scale than the issue asks for (items 3 and 6); the rest are untouched and
say so. Every figure here was produced on 2026-11-18 on the 48 GB development machine and is
quoted with its command.

## 2. A constraint-set version in the verifier key — built, opt-in

**The hazard** (`docs/09-phase4-spans.md` §6): the rVM's verifier key is the preprocessed
commitment of `(program, tier, reduce height)`, salted from two fixed labels. Nothing in it
depends on the AIR's constraint code, so an AIR change that reinterprets a word (phase 4,
opcodes 25 and 27) leaves the key of every earlier program exactly where it was.

**What is built.** `machine::KeyVersion`:

- `Unbound` — today's keys. The salt labels are `rvm/key/mmcs` and `rvm/key/pcs`, verbatim.
  `Machine::new` is `Unbound`, so every key any node holds is unchanged
  (`tests/verifier_key.rs` passes with its pinned caps untouched).
- `Set(n)` — the labels with `/cs<n>` appended. The salts decide the preprocessed commitment,
  so the same program, tier and shape have a different key at every version.
  `Machine::with_key_version(profile, version)` is the only way to get one, and it is
  `#[doc(hidden)]`: no machine a node or an aggregator runs is versioned.

`tests/key_version.rs` (tier 8, seconds):

- the default machine is `Unbound` and its key equals the explicitly unbound one;
- `Unbound`, `Set(11)`, `Set(12)` and `Set(0)` give four pairwise different caps for one
  program, each reproducible;
- a proof made at any of `Unbound`, `Set(11)`, `Set(12)` verifies on a machine at the same
  version and is refused (`VerifyError::Batch`) by the other two — the issue's acceptance line,
  in all six directions.

**What it does and does not bind.** It binds the *key*: a verifier at set `n` builds its keys
from the `/cs<n>` labels, an older key is not equal to any of them, and a proof whose
preprocessed openings are against an older key fails. It does not bind the *program digest*
(`isa::Program::digest`), which a node may also pin: a program whose words did not change keeps
its digest across sets. Capacity lane 7 of the digest's first permutation is free
(`[RVM_PROGRAM_DOMAIN, len, reduce_len, 0]`); putting the version there at the cut moves every
digest with the keys. Not built — it moves every digest in `tests/pins.json`.

**Left for the cut.** (a) Make `Set(RVM_CONSTRAINT_SET)` the only version and give the rVM a
number of its own (`machine::NEXT_CONSTRAINT_SET` is a placeholder: the RV32 machine's
`CONSTRAINT_SET + 1`). (b) The alternative backends (`prove_with`: reference, CUDA) build
unversioned keys; on a versioned machine they return `ProveError::Backend` instead of making a
proof that cannot verify. (c) `shape::RvmKey` and the self-verifier program absorb the key cap,
so every rVM-verifying program digest moves once. (d) The version in the program digest, above.
(e) The full node's admission: admit keys of the current version only, and drop the previous
set's in the same change.

## 3 and 6. The quotient transient and the stage profile — measured at tier 16 only

The issue asks for a stage-level time and heap profile of a current N=1 prove (tier 18). That
was **not run**: the exit twin needs a fresh RV32 bundle fixture (the cached ones predate
constraint set 9 and are refused on load), and proving that fixture is a tier-16 RV32 proof
measured at 5.69 GB per tier-14 step, about 23 GB at tier 16 (`research/docs/05-roadmap.md`,
"ZKVM-111"), past what this session could use on a shared machine. The twin itself is the
15.64 GB run of `docs/07`. The command, for a plain terminal:

```sh
cd recursion && RAYON_NUM_THREADS=16 caffeinate -is cargo test --release --features parallel \
  --test memprofile tier19_exit_twin -- --ignored --nocapture
```

What was run instead is the harness's tier-16 synthetic (`tests/memprofile.rs::
tier16_synthetic_threads`, 60 012 rows, no fixture). The span log is in
`docs/measurements/2026-11-18-tier16-synthetic-memprofile.log`; §"Tier-16 profile" below reads
it.

### Tier-16 profile

`tier16_synthetic_threads`: 1 250 rounds of 16 hinted words stored and sponged, 60 012 rows,
tier 16, Test profile (16 queries; the LDE sizes, and so the heap, are the production ones for
this shape), rate 1/4, `PerInstance`. Three runs, one each, on a machine shared with other
work, so the times are indicative:

| stage (spans directly under `prove_batch`) | no `parallel` | `parallel`, 1 thread | `parallel`, 16 threads | 1 → 16 |
|---|---|---|---|---|
| `randomize polys` (2 spans) | 8.0 s | 7.1 s | 6.2 s | ×1.15 |
| `coset_lde_batch_with_transform` (21) | 2.2 s | 2.5 s | 0.1 s | ×25 |
| `build merkle tree` (4 commits) | 40.9 s | 42.1 s | 4.3 s | ×9.8 |
| `compute quotient` | 22.7 s | 22.4 s | 14.2 s | ×1.6 |
| `FRI prover` | 1.7 s | 1.7 s | 0.8 s | ×2.1 |
| **`prove_batch`** | **78.0 s** | **78.7 s** | **27.6 s** | **×2.85** |
| peak live heap | 3.46 GB | 3.46 GB | 3.95 GB | |
| proof bytes | 220 402 | 218 162 | 219 474 | |

Logs: `docs/measurements/2026-11-18-tier16-synthetic-memprofile{,-parallel-1t,-parallel-16t}.log`.

**Item 6, thread scaling.** At this shape the whole prove scales ×2.85 on 16 threads, and the
table says why. Merkle hashing and the LDEs scale; **`randomize polys` does not scale at all**
(7.1 → 6.2 s) and **`compute quotient` scales ×1.6**. On one thread they are 9 % and 28 % of
the prove; on 16 threads they are 22 % and 51 %, three quarters of the wall between them. So
the `randomize polys` rise `docs/07` saw on the twin (25.6 → 41.7 s) is not a rate effect: the
span is serial (it draws every random row through the one hiding generator), and on a loaded
machine a serial span moves with the load. Whether the quotient's ×1.6 is the constraint
evaluator's own granularity or allocation in the per-row folder was not looked into.

**Item 3, the quotient transient.** The peak is set inside `compute quotient`, in one span: on
the single-thread run the live heap enters the second `compute quotient` span at 1.87 GB,
leaves it at 2.03 GB, and the high-water mark moves from 1.97 to **3.46 GB** in between. The
heap at the end of the prove, with every committed LDE and tree live, is 3.02 GB. So the
transient is about 1.4 GB above the span's own exit level and puts the peak 0.44 GB (15 %)
above what the committed data alone would need. On 16 threads the instances' quotients overlap
and the peak is 3.95 GB, 0.9 GB above the committed level. This is the term `docs/07` and
`docs/09` call likely and untraced; it is traced here at tier 16 for one synthetic program, and
**not** for the N=1 aggregate, whose table mix (the RAM and reduce tables) is different.

What these two say about item 1: at this shape the memory peak is an AIR-degree effect (a
lower-degree chip has fewer quotient chunks and no transient), and the 16-thread wall is
`compute quotient` plus a serial span — neither is the RAM table. The N=1 run is still needed
before pricing a phase 6, because this program has almost no RAM traffic.

## 1, 4, 5, 7, 8 — not started

- **1, the RAM table** (the tallest table; a phase-6 spike): not priced here. Items 3 and 6
  were to decide whether it is attacked through the program or the AIR, and they were not run
  at N=1.
- **4, `REDUCE_MAX_LOG_HEIGHT` 20 → 21**: a key-shape and admission change; not built.
- **5, the remaining row cuts** (S4b, S5, the allocator index bits): not built.
- **7, a tier-17 rung**: not built. It would move `TIERS`, which the verifier's tier check and
  the pinned shapes read.
- **8, the unexamined parameters** (final polynomial length, cap height, commit-phase
  proof-of-work): not priced.
