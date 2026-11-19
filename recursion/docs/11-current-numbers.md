# Current numbers

The one page for the rVM's present rows, tiers and measured figures. The phase records
(`04` to `10`) say how each number was reached and are not rewritten when a later phase moves it;
when a figure here and a figure in a phase record differ, this page is the current one. Update it
in the same change that moves a pin.

As of **constraint set 11** (ZKVM-202, 2026-11-18; `10-phase5-n2-tier19.md`, "Constraint set 11",
which also has the constraint-set-10 figures each row replaced), checked against the sources named
in each row and `tests/pins.json` on 2026-11-19.

## Rows and tiers

A tier `t` holds `2^t − 1` cpu rows.

| what | rows | tier | status | where it is pinned or recorded |
|---|---:|---:|---|---|
| one inner verification, production profile | 236 021 | — | emulated | `10`, "Constraint set 11"; `pins.json` `cpu_rows` |
| production aggregate, N = 1 | 236 347 | 18 | emulated; never proved | `10`, "Constraint set 11"; `tests/aggregate.rs` (`production_n1_…`) |
| production aggregate, N = 2 | 472 311 | 19 | emulated; never proved | same; `production_n2_aggregate_emulates_within_bounds` |
| production aggregate, N = 3 | 708 275 | 20 | emulated; never proved | same; `production_n3_aggregate_emulates_within_bounds` |
| test-profile aggregate, N = 1 | 88 641 | 18 | proved in the suite (pending re-run under set 11) | `10`, "Constraint set 11"; `pins.json` `aggregate_test_n1_cpu_rows` |
| test-profile aggregate, N = 2 | 176 899 | 18 | `#[ignore]`d proof | same |
| test-profile aggregate, N = 3 (the exit twin) | 265 157 | 19 | `#[ignore]`d proof | `tests/aggregate.rs`, `N3_ROWS` |
| tree, production: `rv32n` leaf at L = 2 | 472 311 | 19 | emulated | `pins.json` `tree_measure`; the production N = 2 aggregate (471 119 at set 10, 471 105 in `10` §4's table) |
| tree, production: `rv32r` over the leaf | 254 493 (child 254 177) | 18 | emulated | `10` §4; unchanged by constraint sets 10 and 11 |
| tree, production: `rv32t_leaf` step | 508 735 | 19 | emulated | `10` §4; `tests/tree_measure.rs` |
| tree, test profile: child / `rv32t_leaf` step | 74 605 / 149 586 | 18 | pins wait on the fixture regeneration | `tests/tree.rs` |

Production therefore runs at **tiers 18 to 20** for N = 1 to 3. Earlier documents that speak of
tiers 20 to 23 (`03-gpu-and-self-recursion.md`'s device tables, `07`'s memory projections, older
`#[ignore]` strings) describe the machine before phases 4 and 5.

## FRI and security

| machine | rate | queries | grinding bits | proven bits |
|---|---|---:|---:|---:|
| rVM (`machine::RvmFri`, production) | ¼ | 92 | 24 | 86.38 |
| RV32 machine (`research`, `FriProfile::Production`) | ⅛ | 80 | 20 | 86.41 |

The derivation, what the legacy "260" is, and the zero-knowledge caveat are in one place:
`research/docs/03-privacy.md`, "The security figure, stated once". `07-rvm-rate-quarter.md` has the
rVM's check against `p3-security`.

## Measured and unmeasured

- **No production-profile aggregate or tree proof has been run.** Every production row count
  above is an emulation. Production memory at tiers 18 to 20 is a projection (`09` §5, `10` §6),
  and no host class is claimed.
- The three phase-5 runs `10` §8 lists (the exit twin and the tier-16 synthetic under the heap
  profiler, and the test N = 2 proof) have no logs in `docs/measurements/`: unmeasured.
- The last measured peak for a proved exit twin is phase 4's: 17.19 GB live heap at tier 18, at
  104 150 rows (`09-phase4-spans.md`, summary and §4; one run).
- GPU: the PTX was built and run once on an H100 (2026-09-28, `rand-zkvm-cuda/ptx/PTX_BUILD.md`);
  no production proof has been made on a device, and `03`'s device tables are for tiers 21 to 23.
