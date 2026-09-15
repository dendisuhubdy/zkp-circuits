# 01 — The rVM machine: tables, buses, tiers, and the measured cost of one verified bundle proof

The rVM's proving machine (design spec: `docs/superpowers/specs/2026-09-13-zkvm-m5-recursion-vm-design.md`;
the M5.2 plan: `docs/superpowers/plans/2026-09-14-zkvm-m5-2.md`; the measurement it is cut from and
the three row cuts: `docs/00-recursion-vm.md`). M5.2 builds the machine itself: the tables, the
batch prover/verifier, the tiers, the cheating suite, and — here — the measured numbers for the
exit shape, including the production exit's resource requirement.

Every number in this document was measured on 2026-09-15 on this machine (macOS, 16 cores, 48 GB)
with the crate's documented command, `cargo +1.98.1 test` run from `recursion/`, and is pinned by
a test where the plan asks for one: `tests/pins.json` for the cycle numbers,
`src/programs/verify_rv32.digest` for the program digest, `tests/tables.rs` for the widths and
constraint degrees. Estimates are labelled with their derivation.

## The tables

Seven instances in every batch, plus the reduce chip when the proof declares it (`reduce_log_height
== 0` means no instance — the keccak pattern):

| instance | height rule | width (pinned) | max constraint degree (pinned) | role |
|---|---|---:|---:|---|
| `program` | `pad_height(len + 1, 4)` | 3 witness + 4 preprocessed | 2 | the encoded program, committed by the verifier key's preprocessed cap (R1 — no in-circuit `hc`) |
| `cpu` | `2^tier` | 66 | 8 | fetch (from `program`), 26 one-hot decode selectors, base + extension ALU, the `INV`/`EINV` hint-and-check, control, the `REG`/`RAM`/`POSEIDON2`/`SPONGE`/`REDUCE`/`PUBLIC` sends, the 5-bit register-index and 3-byte address-limb range checks |
| `reg_memory` | declared, `[4, 26]` | 11 | 4 | the register file as cells `2^24 + k`, `k < 32` (R4) — sorted `(addr, ts)`, read-after-write by transition |
| `ram_memory` | declared, `[4, 26]` | 11 | 4 | RAM below `2^24`, same AIR on the `RAM` bus |
| `poseidon2` | declared, `[4, 20]` | 341 | 4 | permutation-per-row, two row kinds (`IS_PERM`, `IS_SPONGE`), round constants baked into `eval` (R9) |
| `public` | fixed at 8 | 7 | 2 | one row per published word; owns the batch's 4 public values (R5, the interface digest) |
| `range` | fixed at 256 | 1 witness + 1 preprocessed | 2 | the `RANGE8` provider |
| `reduce` (optional) | declared, `[4, 20]` | 21 | 3 | the batch-opening reduction, one chip row per column, chained by the descriptor (Task 8) |

**Buses (8, plan R7):** `REG`, `RAM` (both `[addr, ts, value, is_write]`, multiset),
`POSEIDON2 [clk, ptr]`, `SPONGE [clk, state_ptr, src_ptr]`, `PROGRAM [pc, w0..3]`, `RANGE8`,
`PUBLIC [idx, value]`, `REDUCE [clk, descr_ptr]`. Every send count is a selector expression forced
to zero on rows that do not perform the access (`research/AGENTS.md` invariant 2), and every
message column is constrained on every row kind that sends it (invariant 1); `tests/cheating.rs`
proves each one.

**Tiers:** `TIERS = [8, 10, 12, 14, 16, 18, 19, 20, 21, 22, 23]` (plan R2, amended M5.4): stride
2 through the cheap sizes, 19 the post-cut test-profile verifier rung, 21 the production exit
rung, 22 the safety rung, and — added with the CUDA backend (M5.4 Task 2) — **23, the
production N=3 aggregate rung**: host ≥ 160 GB (M5.3's derived ~127 GB oracle), device 80 GB
class (`docs/03-gpu-and-self-recursion.md`'s device model). A rung no CPU-only box in this
fleet has, pinned by `for_cycles`, not by a proof.

## The measured numbers

Final, per verified inner proof (one RV32 bundle proof at **constraint set 6**, **9 instances**),
from the emulator's own event log and pinned in `tests/pins.json` (production digest
`8901cec9c1681c9674f1e5582805d625c60b20d9f69be546da982622f36e0bda`):

| | `FriProfile::Test` (16 q) | `FriProfile::Production` (80 q) |
|---|---:|---:|
| cpu rows | 441 643 | **1 968 619** |
| Poseidon2 permutations | 11 205 | **51 605** |
| memory accesses (RAM) | 597 021 | 2 705 197 |
| register accesses | 992 729 | 4 278 681 |
| reduce-chip rows | 31 232 | 156 160 |
| program instructions | 443 686 | 1 978 422 |
| witness words | 43 344 | 199 760 |
| **declared heights** | 19, 20, 20, 14, 15, 19 | 21, 23, 22, 16, 18, 21 |

(Heights in `chips()` order: cpu, reg, ram, poseidon2, reduce, program; public is fixed at 2^3
and range at 2^8.)

### The three cuts and the gates (spec §7's decision, executed)

| stage | cpu rows (production) | Δ | the plan's prediction | gate |
|---|---:|---:|---|---|
| M5.1 + Task 4 (R5) | 5 683 021 | — | — | over 2^21 · 0.75 — liveness runs |
| Task 7 (liveness) | 4 052 455 | −28.7 % | ~3.6 M (guessed 85–90 % of 2 454 511 spill/reload rows; measured kill 66 %) | 4 052 455 > 1 572 864 — **fires** |
| Task 8 (`REDUCE`) | 2 240 988 | −44.7 % | ~2.5 M (beat it: the compiled reduction was ~11.6 rows/column, not ~7) | 2 240 988 > 1 572 864 — **fires** |
| Task 9 (`SPONGE`) | 1 968 619 | −12.1 % | ~1.9–2.0 M (in band; absorb bookkeeping ~8.8 rows/block, not ~15–20) | **tier 21: 1 968 619 < 2^21, 6.1 % headroom** |

## The test-profile twin (Task 10's in-suite exit shape)

The twin proves the post-cut verifier program's execution over one real `FriProfile::Test` bundle
proof and verifies the rVM proof natively (`tests/exit.rs::twin_...`, `#[ignore]`d with the wall
times). Measured 2026-09-15:

| | measured |
|---|---:|
| cpu rows / tier | 441 643 / **19** |
| prove time | **1 707.7 s** (on this box, at load ~5 with other cargo sessions running) |
| verify time | **18.31 s** — dominated by the 2^19-row preprocessed program key build; the batch verify itself is sub-second |
| proof size | **327 321 bytes** |
| peak resident | **~15 GB observed** (watchdog samples; the completed run sampled ≤ 10.4 GB, the earlier timed-out attempt 15.0 GB) |

## The production exit's resource requirement (derived, not measured)

The production exit is the same proof at `FriProfile::Production` over one real cs6 bundle proof:
2 240 988 fewer rows than the pre-cut rehearsal, tier 21. Its peak resident memory is derived from
the measured declared heights and the calibrated oracle model (the model the M5.2 plan's sizing
section calibrates against the rehearsal, which peaked at 28.5 GB RSS against a 32.1 GB modelled
oracle — a factor of 0.89):

| instance | height | width | committed oracle (`2^(h+4) · (w+4) · 8 B`) |
|---|---:|---:|---:|
| cpu | 2^21 | 66 | 18.79 GB |
| reg_memory | 2^23 | 11 | 16.11 GB |
| ram_memory | 2^22 | 11 | 8.05 GB |
| poseidon2 | 2^16 | 341 | 2.89 GB |
| program | 2^21 | 3 | 1.88 GB |
| reduce | 2^18 | 21 | 0.84 GB |
| public / range | 2^3 / 2^8 | 7 / 1 | ~0 |
| **total** | | | **48.6 GB** |

Peak estimate: the oracle floor of **48.6 GB**, times the rehearsal's observed 0.89
(≈ **43 GB best case**) to the conservative 1.25 multiplier (≈ **61 GB**). So:

- **The firm requirement is ≥ 64 GB** — the same class `research/docs/04-guests.md` documents for
  the tier-18 EVM and tier-20 sBPF proofs. The exit is `#[ignore]`d with that requirement and its
  command; it is not attempted on this 48 GB machine.
- **48 GB does not fit**: the committed oracle alone (48.6 GB) exceeds the box before any
  quotient, permutation or FRI-tree working set — and the two pre-cut rehearsal attempts died by
  jetsam below 30 GB under concurrent cargo load. 48 GB + swap is not plausible: the working set
  is the oracle itself, and the NTT/Merkle phases page randomly over the whole of it.
- The proof size at this shape is estimated at ~0.5–0.6 MB (the plan's derivation: ~640 opened
  columns per query × 80 queries × ~8 B + commitments/paths), inside the fullnode's 2 MiB cap
  with ~3.5× headroom; the twin's measured size above is the test-profile anchor for it. Task 10's
  production run measures the real number.

## The cheating suite

26 tests in `tests/cheating.rs`, one per soundness item, each a `rejects()` — spec §7's list
against the final machine: a wrong arithmetic result, a broken pc chain, a bad `INV` hint, an
address ≥ 2^24 with forged limbs, a register write to `r0` surfacing, a fetch count short by one,
a skipped permutation and an extra one, a memory `VALUE` tamper (the "wrong Merkle sibling"/"wrong
fold value" shape), a forged public value (batch and table), a proof of one program verified
against another (R1), a wrong tier, an out-of-range tier, the padding-row selector tamper
(invariant 2), a memory delta-limb forgery, a published value out of order, and the Task 8/9
tranches (the reduce chip's chain, a dropped column, a forged descriptor field, a dispatch with no
chip run, a declared-no-table degree mismatch; the absorb row's wrong source cell, a skipped
absorb, a sponge row claiming the plain kind). The permutation-equality contract — the chip's
permutation equals the reference on 1 000 random states — is a proof in `tests/cpu.rs`, its
sponge twin in `tests/precompiles.rs`.

## What M5.3 adds

`docs/02-aggregate.md`: the N-generic aggregate program — one counted loop over `N` inner
proofs of one shape, the interface digest over `[inner_vk_digest ‖ N ‖ 34·N]`, one registered
program digest per shape — with the measured per-N economics (test profile N=1..3 in
`tests/pins.json`), the chain-facing `aggregate` / `verify_aggregate` API, the two chain-side
corrections (sealed history carries every covered bundle's declared shape; admission
shape-checks every covered bundle), and the fullnode admission stub's specification and test
vectors.
