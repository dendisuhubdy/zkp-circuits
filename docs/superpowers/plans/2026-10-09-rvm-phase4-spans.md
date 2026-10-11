# rVM Phase 4 — the Merkle Spans Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Cut one production inner verification from 585 686 cpu rows (tier 20) to ≤ 524 287 (tier 19), target ≈ 317 k, with four cuts to the two Merkle spans: cap select, allocator re-homing, no digest copies, immediate-address `SPONGE`/`COMPRESS`.

**Architecture:** Three cuts are DSL/program changes that move only program digests (`programs/rv32.rs`, `dsl/hash.rs`, `dsl/builder.rs`). The fourth changes the meaning of opcodes 25/27's fourth word from a register index to an absolute address immediate. It reuses the cpu AIR's existing immediate-form constraint, so the AIR gets no new column and no change of degree. Every pin is re-recorded once, in Task 5. Measurement and `docs/08` follow in Task 6.

**Tech Stack:** Rust 1.98.1, Plonky3 0.7.0 (vendored forks), crate `recursion` in the circuits repo.

**Spec:** `docs/superpowers/specs/2026-10-09-rvm-phase4-spans-design.md`. The priced spike behind every number is `recursion/docs/measurements/2026-10-08-merkle-spike-findings.md`, with its code in `recursion/docs/measurements/2026-10-08-merkle-spike.patch` (env-flag gated; read it for shape, never apply it).

**Worktree:** `~/rand-worktrees/circuits-phase4`, branch `feat/rvm-phase4-spans`, base circuits `main` 71e1a04. Every command runs from `~/rand-worktrees/circuits-phase4/recursion` unless stated.

## Global Constraints

- Program and ISA cuts only: the inner RV32 machine, `inner_vk_digest`, the interface `[vk ‖ N ‖ B(8) ‖ 35·N]`, the FRI profiles (inner 80/8/20; rVM `RvmFri` Production (2, 92, 24) / Test (2, 16, 4)), the quotient layout, the reduce chip and the poseidon2 table never move.
- B/B′ use **absolute** immediates through the existing immediate-form constraint (`B0 = B`, `B1 = 0`): no new column, no degree change, `Op::COUNT` stays 30.
- `NUM_REGS`, `ALLOCATABLE` (r1..r25) and `SCRATCH` (r26..r31) do not change.
- Re-homing applies to `Liveness::On` builds only (both `Precompiles` settings). `Liveness::Off` stays the byte-for-byte pre-liveness reference.
- The cap select (D1) is `Precompiles::On` only; `Precompiles::Off` keeps the indicator dot product as the differential reference.
- The tier gate decides: after Task 1 the production profile must read ≤ 524 287 cpu rows, else stop and report.
- Band rule: each cut's measured Δ lands within ±15 % of its expected Δ (table below), or the task report explains why.
- Never quote macOS RSS as a memory number; memory figures come from `tests/memprofile.rs`'s heap profiler only.
- No `unsafe`, no new dependencies, no env-flag gating in shipped code (the spike's `spike()` flags do not come across).
- Commits end with the trailer `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.
- zsh: quote every glob in shell commands (`'*.log'`). An unquoted glob that matches nothing aborts the whole command list.

**Expected rows, production profile, in the order of work** (from the spike's combinations):

| after | cpu rows | Δ from previous | ±15 % band on Δ |
|---|---:|---:|---|
| baseline | 585 686 | — | — |
| Task 1 (D1) | 513 994 | −71 692 | −60 938 … −82 446 |
| Task 2 (A) | 386 698 | −127 296 | −108 202 … −146 390 |
| Task 3 (D2) | 367 339 | −19 359 | −16 455 … −22 263 |
| Task 4 (B + B′) | 317 315 | −50 024 | −42 520 … −57 528 |

**The profile command** (the one measurement every task re-runs; emulation only; seconds once the production fixture is cached):

```bash
cargo test --release -p recursion --test profile -- --ignored --nocapture 2>&1 | tee /tmp/phase4-profile.log
```

Read the production section's total cpu rows and the `input_root` / `commit_root` span lines. Copy the log to `docs/measurements/2026-10-09-span-profile-<task>.log`; that copy is the record.

**The targeted suite** (Tasks 1–4; the full suite is Task 5's):

```bash
cargo test --release -p recursion --test dsl --test allocator --test emulator --test precompiles \
  --test transcript --test isa --test cpu --test cheating --test tables --test program 2>&1 | tail -40
```

Pin tests (`tests/exit.rs`, `tests/aggregate.rs`, `tests/self_verify.rs`, `tests/verifier_key.rs`, `tests/memprofile.rs`, `src/programs/verify_rv32.digest`, `tests/pins.json`) are expected to fail on row counts and digests from Task 1 on. Task 5 re-records them. Tasks 1–4 must not add any other failure.

## Review Focus

1. **A handle written in place after its definition** (`counted_loop`'s counter, `FADDI ctr, ctr, −1`) is re-homed, then evicted for free from a stale spill cell. Expected: such handles are never re-homed. The `Slot::mutable` guard plus Task 2's counter test cover this.
2. **A re-home claim inside a loop body evicts a pre-loop resident.** Today's replay panics on this at `LoopEnd`, so the build would fail even with valid code. Expected: re-homing inside a loop never displaces a handle defined before the innermost open loop. Task 2's loop-pressure test covers this.
3. **A re-homed handle dies while resident.** Expected: both its register and its retained spill cell are freed, so cells are reused and the arena does not grow. Task 2's re-home/die cycle test checks `stats.cells` against the non-re-homing bound.
4. **A walk caller reads the leaf digest after the in-place walk.** Expected: the leaf is clobbered by design, so it must not alias siblings, injection rows or the hash scratch (build-time assertion). The doc says the walk consumes it. Task 3 tests the aliasing refusal.
5. **A `SPONGE`/`COMPRESS` immediate near the top of the address space** (`b + 3 ≥ 2^24`). Expected: the emulator refuses it with `AddressOutOfRange` naming the pc, and the AIR's group-2 limbs refuse a forged trace. Task 4 has both tests.

---

### Task 1: Baseline and D1, the cap select by register-offset `LOAD`

**Files:**
- Modify: `src/dsl/builder.rs` (add `Builder::load_offset` next to `load_ext_offset`, ≈ line 569)
- Modify: `src/dsl/hash.rs` (add `pub fn assert_cap_entry`)
- Modify: `src/programs/rv32.rs:813-840` (`assert_cap_eq`: the `Precompiles::On` path calls `hash::assert_cap_entry`; the dot product stays for `Off`)
- Test: `tests/dsl.rs`
- Create: `docs/measurements/2026-10-09-span-profile-baseline.log`, `docs/measurements/2026-10-09-span-profile-d1.log`

**Interfaces:**
- Produces: `Builder::load_offset(&mut self, base: Ptr, k: i64, off: Felt) -> Felt`, which returns `mem[addr_of(base) + k + off]`, with `off` a runtime value.
- Produces: `hash::assert_cap_entry(b: &mut Builder, got: Digest, caps: Ptr, bits: [Felt; 2], name: &str)`. `caps` is 16 contiguous cells (four digests); the function asserts `got == caps[4·b0 + 8·b1 .. +4]` lane by lane under `name`.

- [ ] **Step 1: Record the baseline.** Run the profile command and confirm production reads 585 686 cpu rows. Save the log as `docs/measurements/2026-10-09-span-profile-baseline.log`. Run the targeted suite and record its pass count in the report (all pass on the base).

- [ ] **Step 2: Write the failing tests** in `tests/dsl.rs`:

```rust
/// D1's gadget: a register offset picks one of four contiguous digests, for every bit pair, and a
/// mismatch traps at the caller's name.
#[test]
fn assert_cap_entry_selects_each_of_the_four_digests_by_its_bits() {
    use recursion::dsl::{hash, Digest};
    for idx in 0..4u64 {
        let mut b = Builder::new(Checkpoints::Off);
        let caps = b.alloc(16);
        for c in 0..16u64 {
            let v = b.constant(F::from_u64(100 + c));
            b.store(caps, c as i64, v);
        }
        let got = b.alloc(4);
        for lane in 0..4u64 {
            let v = b.constant(F::from_u64(100 + 4 * idx + lane));
            b.store(got, lane as i64, v);
        }
        let b0 = b.constant(F::from_u64(idx & 1));
        let b1 = b.constant(F::from_u64(idx >> 1));
        hash::assert_cap_entry(&mut b, Digest(got), caps, [b0, b1], "cap entry");
        let one = b.constant(F::ONE);
        b.public(one);
        assert_eq!(run(b, &[]), vec![F::ONE], "index {idx} selects digest {idx}");
    }
}

#[test]
fn assert_cap_entry_traps_at_its_name_on_the_wrong_digest() {
    use recursion::dsl::{hash, Digest};
    let mut b = Builder::new(Checkpoints::Off);
    let caps = b.alloc(16);
    for c in 0..16u64 {
        let v = b.constant(F::from_u64(100 + c));
        b.store(caps, c as i64, v);
    }
    let got = b.alloc(4);
    for lane in 0..4u64 {
        let v = b.constant(F::from_u64(100 + lane)); // digest 0
        b.store(got, lane as i64, v);
    }
    let b0 = b.constant(F::ONE); // ...checked against digest 1
    let b1 = b.constant(F::ZERO);
    hash::assert_cap_entry(&mut b, Digest(got), caps, [b0, b1], "input opening root[main]");
    let p = b.finish();
    match execute(&p, &[], 1_000_000) {
        Err(ExecError::InverseOfZero { pc }) => assert_eq!(p.checkpoint_at(pc), Some("input opening root[main]")),
        other => panic!("expected a trap, got {other:?}"),
    }
}

#[test]
fn load_offset_adds_a_runtime_offset_to_a_compile_time_address() {
    let mut b = Builder::new(Checkpoints::Off);
    let p = b.alloc(16);
    for c in 0..16u64 {
        let v = b.constant(F::from_u64(7 * c));
        b.store(p, c as i64, v);
    }
    let off = b.hint();
    let x = b.load_offset(p, 3, off);
    b.public(x);
    assert_eq!(run(b, &[F::from_u64(8)]), vec![F::from_u64(7 * 11)]);
}
```

Check the module paths before running: if `hash` or `Digest` is not re-exported at `recursion::dsl::{hash, Digest}`, use the path `tests/transcript.rs` imports them by.

- [ ] **Step 3: Run them and see them fail**

Run: `cargo test --release -p recursion --test dsl assert_cap_entry load_offset`
Expected: compile errors, because `assert_cap_entry` and `load_offset` do not exist yet.

- [ ] **Step 4: Implement `load_offset`** in `src/dsl/builder.rs`, next to `load_ext_offset`:

```rust
    /// `mem[addr_of(base) + k + off]`, `off` a runtime value: one `LOAD` with the offset's register
    /// as `ra` and the compile-time address as the immediate. The cpu AIR range-checks the sum, so
    /// an offset that leaves the address space is unprovable; the caller bounds `off` (D1's cap
    /// select builds it from two constrained bits, `off ∈ {0, 4, 8, 12}`).
    pub fn load_offset(&mut self, base: Ptr, k: i64, off: Felt) -> Felt {
        self.begin();
        let ro = self.materialise(off.0);
        let at = imm(self.addr_of(base) as i64 + k);
        let (id, rd) = self.new_handle(1);
        self.emit(Op::Load, rd, ro, BRef::Imm(at));
        Felt(id)
    }
```

- [ ] **Step 5: Implement `assert_cap_entry`** in `src/dsl/hash.rs`:

```rust
/// D1 (phase 4): the digest a walk reached, checked against the cap entry at index `b0 + 2·b1` by
/// address, not by an indicator dot product: `off = 4·b0 + 8·b1`, then one register-offset `LOAD`
/// a lane. `caps` is the four digests as sixteen contiguous cells. The bits must be boolean —
/// `DslChallenger::sample_bits` constrains every bit where it is born — so `off ∈ {0, 4, 8, 12}`
/// and the load stays inside the sixteen cells; the cpu AIR range-checks the address regardless.
/// The pattern is the one `docs/06` Cut E1 ruled sound for the own-slot check.
pub fn assert_cap_entry(b: &mut Builder, got: Digest, caps: Ptr, bits: [Felt; 2], name: &str) {
    let o0 = b.mul_const(bits[0], F::from_u64(DIGEST_ELEMS as u64));
    let o1 = b.mul_const(bits[1], F::from_u64(2 * DIGEST_ELEMS as u64));
    let off = b.add(o0, o1);
    for lane in 0..DIGEST_ELEMS as i64 {
        let c = b.load_offset(caps, lane, off);
        let g = b.load(got.0, lane);
        b.assert_eq(g, c, name);
    }
}
```

Use whatever name `hash.rs` already imports the base field as (`F`); add the import if it is missing.

- [ ] **Step 6: Route `assert_cap_eq` through it** under `Precompiles::On`. At the top of `assert_cap_eq` in `src/programs/rv32.rs`:

```rust
    if b.precompiles() == Precompiles::On {
        // D1: the four caps are one contiguous sixteen-cell run (`read_cap` / `constant_cap`); the
        // select is by address. `Off` keeps the dot product below as the differential reference.
        for j in 1..4 {
            assert_eq!(b.addr_of(cap[j].0), b.addr_of(cap[0].0) + (j * DIGEST_ELEMS) as u64,
                       "the four cap digests must be contiguous for the address select");
        }
        hash::assert_cap_entry(b, got, cap[0].0, [bits[0], bits[1]], name);
        return;
    }
```

Update `assert_cap_eq`'s doc comment so it describes both paths.

- [ ] **Step 7: Run the new tests and the targeted suite**

Run: `cargo test --release -p recursion --test dsl assert_cap_entry load_offset`, which should pass. Then run the targeted suite: it should pass apart from failures in the pin tests listed under Global Constraints. Also run `cargo test --release -p recursion --test verifier the_off_replay_reproduces_the_pre_liveness_program_byte_for_byte`. It must **still pass with the unchanged `c580415b…` digest**, because D1 is On-only. That test's acceptance half also proves a real proof through both builds.

- [ ] **Step 8: Measure the gate.** Run the profile command and save the log as `docs/measurements/2026-10-09-span-profile-d1.log`. Production must read **≤ 524 287** cpu rows (expected ≈ 513 994). If it reads more, **STOP**: commit nothing further and report BLOCKED with the log. Report the Δ against the band.

- [ ] **Step 9: Commit**

```bash
git add src/dsl/builder.rs src/dsl/hash.rs src/programs/rv32.rs tests/dsl.rs docs/measurements/2026-10-09-span-profile-baseline.log docs/measurements/2026-10-09-span-profile-d1.log
git commit -m "recursion: phase 4 D1 — the cap select by register-offset LOAD (off = 4·b0 + 8·b1), Precompiles::On; production <N> rows (tier 19)

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

(Replace `<N>` with the measured count.)

---

### Task 2: A, re-homing reloads in the allocator

**Files:**
- Modify: `src/dsl/builder.rs`: `Slot` (add `mutable: bool`), `Stats` (add `rehomes: usize`), `counted_loop` (mark the counter mutable), `replay` (the `Mat` arm, the `LoopTop`/`LoopEnd`/`BranchTop`/`BranchEnd` arms track nesting, a `clean` vector), `claim` (take `clean: &[bool]`; skip the `STORE` for a clean victim that still has its cell)
- Test: `tests/allocator.rs`
- Create: `docs/measurements/2026-10-09-span-profile-a.log`

**Interfaces:**
- Consumes: nothing from Task 1.
- Produces: `Stats::rehomes: usize`, the number of reloads that landed in an allocatable register. Task 6's docs quote it.

**The rule, in full.** At a `Mat { id }` of a handle that is spilled (`home[id].is_none()`), re-home it into an allocatable register instead of a scratch slot when **all** of the following hold:
1. `live` (Liveness::On) and `slots[id].width == 1` and `!slots[id].mutable`;
2. no `if_eq` body is open (`branch_depth == 0`);
3. if a loop is open, `def_idx[id] > innermost_loop_top` (the handle was defined in the innermost body);
4. the handle has a next `Mat` use after `i`, and either a register in `ALLOCATABLE` is vacant or some unpinned resident's next use is farther than that `Mat`. The pinned set is: (a) every non-scratch register already in `mat_out` for this group; (b) every home register the group's following `Instr`s read or write (`rd`, `ra`, `b`) and every home of a following `Mat` (scan `ops[i + 1..]` until the next `Op2::Group`); (c) if a loop is open, the home of every resident with `def_idx < innermost_loop_top`, so a re-home inside a loop never moves a pre-loop handle.

When it fires: `claim(1, &pinned, …)` the register, emit `LOAD reg, [cell]`, set `home[id] = Some(reg)`, `regs[reg] = Some(id)`, push it onto `residents`, `live_count += 1` (update `live_max`), `clean[id] = true`, `stats.reloads += 1`, `stats.rehomes += 1`. The handle **keeps** its cell. In `claim`, a victim with `clean[victim] && cells[victim].is_some()` is evicted without a `STORE` and keeps its existing cell (no new cell allocated). The death path already frees both register and cell; check it does so for a re-homed handle.

The spike patch's `SPIKE_REHOME` hunk (`docs/measurements/2026-10-08-merkle-spike.patch`, the `Op2::Mat` arm) is the reference shape. It lacks rule 1's `mutable` and rule 4(c): add both.

- [ ] **Step 1: Write the failing tests** in `tests/allocator.rs`. Use the file's existing imports and its `publics` helper, and add what is missing:

```rust
use recursion::dsl::{Builder, Checkpoints};
use recursion::emulator::execute;
use recursion::isa::{Op, F};
use p3_field::PrimeCharacteristicRing;

/// 40 constants (more than the 25 allocatable registers), then every one read three times, far
/// apart: without re-homing every read after the first spill is a reload; with it, a reload
/// whose next use is near takes a real register and the later reads hit it.
fn pressure_program(b: &mut Builder) -> F {
    let vals: Vec<_> = (1..=40u64).map(|k| b.constant(F::from_u64(k))).collect();
    let mut acc = b.zero();
    for _round in 0..3 {
        for v in &vals {
            let t = b.mul(*v, *v);
            acc = b.add(acc, t);
        }
    }
    b.public(acc);
    F::from_u64(3 * (1..=40u64).map(|k| k * k).sum::<u64>())
}

#[test]
fn a_reload_rehomes_into_a_real_register_and_the_result_is_unchanged() {
    let mut b = Builder::new(Checkpoints::Off);
    let want = pressure_program(&mut b);
    let (p, stats) = b.finish_stats();
    assert!(stats.rehomes > 0, "the pressure program must re-home: {stats:?}");
    assert_eq!(execute(&p, &[], 1_000_000).unwrap().public, vec![want]);
}

/// Rule 4(b): an instruction whose two operands are both spilled — the re-home claim for one must
/// not evict the register the other was just loaded into. A wrong eviction changes the sum.
#[test]
fn a_rehome_never_evicts_an_operand_of_the_instruction_it_feeds() {
    let mut b = Builder::new(Checkpoints::Off);
    let vals: Vec<_> = (1..=60u64).map(|k| b.constant(F::from_u64(k))).collect();
    let mut acc = b.zero();
    for w in vals.windows(2).rev() {
        let t = b.mul(w[0], w[1]);
        acc = b.add(acc, t);
    }
    for w in vals.windows(2) {
        let t = b.sub(w[1], w[0]);
        acc = b.add(acc, t);
    }
    b.public(acc);
    let want: u64 = (1..60u64).map(|k| k * (k + 1)).sum::<u64>() + 59;
    let (p, stats) = b.finish_stats();
    assert!(stats.rehomes > 0, "{stats:?}");
    assert_eq!(execute(&p, &[], 1_000_000).unwrap().public, vec![F::from_u64(want)]);
}

/// Rule 2: inside an `if_eq` body every reload goes to scratch (r26..r31). A re-home there would
/// move a register on one path only, which the replay refuses (or worse).
#[test]
fn no_reload_inside_an_if_eq_body_lands_in_an_allocatable_register() {
    let mut b = Builder::new(Checkpoints::Off);
    let vals: Vec<_> = (1..=40u64).map(|k| b.constant(F::from_u64(k))).collect();
    let cell = b.alloc(1);
    let z = b.zero();
    b.store(cell, 0, z);
    let x = b.hint();
    let one = b.constant(F::ONE);
    b.if_eq(x, one, |b| {
        let mut acc = b.zero();
        for v in vals.iter().chain(vals.iter()) {
            acc = b.add(acc, *v);
        }
        b.store(cell, 0, acc);
    });
    let out = b.load(cell, 0);
    b.public(out);
    for v in &vals { b.public(*v); }
    let p = b.finish();
    // The body is the pc range between the JNE and its target.
    let jne = p.instrs.iter().position(|i| i.op == Op::Jne).unwrap();
    let end = p.instrs[jne].b.as_canonical_u64() as usize;
    for (pc, ins) in p.instrs[jne + 1..end].iter().enumerate() {
        if ins.op == Op::Load && ins.ra == 0 {
            assert!(ins.rd >= 26, "pc {}: a reload inside the if_eq body went to r{}", jne + 1 + pc, ins.rd);
        }
    }
    let taken = execute(&p, &[F::ONE], 1_000_000).unwrap().public;
    let skipped = execute(&p, &[F::ZERO], 1_000_000).unwrap().public;
    assert_eq!(taken[0], F::from_u64(2 * 820));
    assert_eq!(skipped[0], F::ZERO);
    assert_eq!(taken[1..], skipped[1..]);
}

/// Rule 3 and 4(c): a loop body under pressure that reloads body-defined values (which may
/// re-home) while pre-loop handles stay resident across it — the build must not trip the
/// replay's loop invariant, and every iteration computes the same thing.
#[test]
fn a_loop_body_rehomes_only_its_own_values_and_never_moves_a_pre_loop_handle() {
    let mut b = Builder::new(Checkpoints::Off);
    let outer: Vec<_> = (1..=10u64).map(|k| b.constant(F::from_u64(k))).collect();
    let cell = b.alloc_absolute(1);
    let acc_cell = b.alloc(1);
    let z = b.zero();
    b.store(acc_cell, 0, z);
    let n = b.constant(F::from_u64(3));
    b.counted_loop_mem(cell, n, |b| {
        let inner: Vec<_> = (1..=30u64).map(|k| b.constant(F::from_u64(k))).collect();
        let mut acc = b.load(acc_cell, 0);
        for _ in 0..2 {
            for v in &inner {
                acc = b.add(acc, *v);
            }
        }
        for v in &outer {
            acc = b.add(acc, *v);
        }
        b.store(acc_cell, 0, acc);
    });
    let out = b.load(acc_cell, 0);
    b.public(out);
    let p = b.finish();
    assert_eq!(execute(&p, &[], 1_000_000).unwrap().public, vec![F::from_u64(3 * (2 * 465 + 55))]);
}

/// Rule 1: `counted_loop`'s counter is decremented in place (`FADDI ctr, ctr, −1`), so its spill
/// cell goes stale after the first iteration; it must never be re-homed (a free eviction would
/// then resurrect the stale count). The body reads the counter under pressure.
#[test]
fn the_counted_loop_counter_is_never_rehomed() {
    let mut b = Builder::new(Checkpoints::Off);
    let cell = b.alloc(1);
    let z = b.zero();
    b.store(cell, 0, z);
    let n = b.constant(F::from_u64(5));
    b.counted_loop(n, |b, i| {
        let mut acc = b.load(cell, 0);
        acc = b.add(acc, i);
        b.store(cell, 0, acc);
    });
    let out = b.load(cell, 0);
    b.public(out);
    let p = b.finish();
    assert_eq!(execute(&p, &[], 1_000_000).unwrap().public, vec![F::from_u64(5 + 4 + 3 + 2 + 1)]);
}

/// Review Focus 3: a re-homed value keeps its spill cell and gives it back when it dies, so a long
/// run of re-home/die cycles does not grow the spill arena past the run without them.
#[test]
fn rehomed_values_return_their_cells_when_they_die() {
    let mut b = Builder::new(Checkpoints::Off);
    let mut acc = b.zero();
    for block in 0..50u64 {
        let vals: Vec<_> = (1..=30u64).map(|k| b.constant(F::from_u64(block * 100 + k))).collect();
        for _ in 0..2 {
            for v in &vals {
                acc = b.add(acc, *v);
            }
        }
    }
    b.public(acc);
    let (_p, stats) = b.finish_stats();
    assert!(stats.rehomes > 0, "{stats:?}");
    assert!(stats.cells < 200, "the arena grew with the number of blocks: {} cells", stats.cells);
}
```

The `if_eq` test reads `JNE`'s target as its fourth word. Check `emulator.rs`'s `Jne` arm: if the target is relative or stored elsewhere, adjust the range computation to match it. Whatever you find, the test's claim stays the same: no allocatable-register `LOAD … ra=0` inside the body.

`the_counted_loop_counter_is_never_rehomed` passes **today** as well: it guards a regression and does not fail first. That is expected. Say so in the report.

- [ ] **Step 2: Run the tests and see them fail.** `cargo test --release -p recursion --test allocator`. Expected: compile errors on `stats.rehomes`. Once the field exists (step 3 adds it, initialised to zero), the `rehomes > 0` assertions fail.

- [ ] **Step 3: Implement the rule above** in `src/dsl/builder.rs`:
  - `Slot { mutable: bool, … }`: `false` everywhere a slot is pushed. `counted_loop` sets `self.slots[ctr as usize].mutable = true` right after `new_handle`.
  - `Stats { rehomes: usize, … }` (it derives `Default`), with a doc line.
  - In `replay`: `let mut clean = vec![false; self.slots.len()]`, `let mut branch_depth = 0usize`, and `let mut loop_tops: Vec<u32>`. Push at `LoopTop`, pop at `LoopEnd`, `+= 1` at `BranchTop`, `-= 1` at `BranchEnd`.
  - The `Mat` arm: try the re-home first, as the rule says; otherwise fall through to today's scratch reload unchanged.
  - `claim(…, clean: &[bool])`: after the victim's register is released and before a cell is chosen, `if clean[id as usize] && cells[id as usize].is_some() { continue; }`. Pass `&clean` from both call sites (the `Def` arm passes it too).
  - Keep `claim`'s `Off`-policy branch unchanged. Re-homing never runs when `!live`, so `Liveness::Off` emits exactly what it does today.

- [ ] **Step 4: Run the tests and see them pass.** Run `cargo test --release -p recursion --test allocator`, then `--test dsl`. In `tests/dsl.rs`, `the_program_digest_of_the_sample_program_is_stable` passes if the sample program has no reloads. If it fails, the sample re-homed: re-record `tests/dsl-sample.digest` and say so in the report.

- [ ] **Step 5: Run the targeted suite and the Off-replay test.** The targeted suite should pass apart from the listed pin tests. Run `cargo test --release -p recursion --test verifier the_off_replay_reproduces_the_pre_liveness_program_byte_for_byte`: it must still pass with `c580415b…`, which shows Liveness::Off is untouched and both builds accept the real proof. Also run `cargo test --release -p recursion --test self_verify`: the round trips must pass, and only its digest and `CycleReport` pins may fail.

- [ ] **Step 6: Measure.** Run the profile command and save the log as `docs/measurements/2026-10-09-span-profile-a.log`. Expect ≈ 386 698. Report the Δ against the band, plus `stats.rehomes`, `reloads` and `live_max` for the production build (print them from a scratch test if the profile does not).

- [ ] **Step 7: Commit**

```bash
git add src/dsl/builder.rs tests/allocator.rs docs/measurements/2026-10-09-span-profile-a.log
git commit -m "recursion: phase 4 A — re-homing reloads (Belady, Liveness::On): never in an if_eq body, in a loop only body-defined values and never displacing a pre-loop handle, never a mutable counter; a re-homed value keeps its cell; production <N> rows

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 3: D2, no digest copies in the Merkle walk

**Files:**
- Modify: `src/dsl/hash.rs`: `merkle_walk` and `merkle_walk_with_injections` drop the `out` parameter and return `Digest`. The `On` path compresses over `leaf` in place. The `Off` path copies its result back into `leaf`. Add the aliasing assertions and update both docs (row counts drop by 16 under `On`: `2·levels − 1` rows when level 0 has no `FADDI`; measure and state it).
- Modify: `src/programs/rv32.rs` (`emit_input_round_root`, `emit_commit_root`: no `out` alloc; take the returned digest)
- Modify: `tests/transcript.rs` (3 call sites), `tests/verifier.rs` (2), `tests/precompiles.rs` (1): read the returned digest
- Modify: `tests/verifier.rs`: re-record the Off-replay digest (it moves here) with a history clause
- Create: `docs/measurements/2026-10-09-span-profile-d2.log`

**Interfaces:**
- Produces: `pub fn merkle_walk(b: &mut Builder, leaf: Digest, index_bits: &[Felt], siblings: Ptr, levels: usize) -> Digest` and `pub fn merkle_walk_with_injections(b: &mut Builder, leaf: Digest, index_bits: &[Felt], siblings: Ptr, levels: usize, injections: &[Injection]) -> Digest`. The returned digest **is** `leaf`, overwritten: the walk consumes the caller's leaf.

- [ ] **Step 1: Write the failing aliasing test** in `tests/precompiles.rs`:

```rust
/// D2: the walk overwrites the leaf with the digest it reaches, so a leaf that aliases the siblings
/// would be read back corrupted — refused at build time.
#[test]
#[should_panic(expected = "the walk consumes its leaf")]
fn a_walk_whose_leaf_aliases_its_siblings_is_refused_at_build() {
    use recursion::dsl::{hash, Builder, Checkpoints, Digest, Liveness, Precompiles};
    let mut b = Builder::with_opts(Checkpoints::Off, Liveness::On, Precompiles::On);
    let sibs = b.alloc(16);
    let bits: Vec<_> = (0..4).map(|_| b.zero()).collect();
    let leaf = Digest(b.offset(sibs, 4));
    let _ = hash::merkle_walk(&mut b, leaf, &bits, sibs, 4);
}
```

(Use the import paths `tests/precompiles.rs` already uses.)

- [ ] **Step 2: Change the signatures.** Update every caller (`src/programs/rv32.rs` ×2, `tests/transcript.rs` ×3, `tests/verifier.rs` ×2, `tests/precompiles.rs` ×1) to `let reached = hash::merkle_walk…(…)` and use `reached` where `out` / `root` was read. In `merkle_walk_via_compress_matches_the_compiled_walk`, the On build and the Off build must still agree on the returned digest.

- [ ] **Step 3: Implement.** In `merkle_walk_with_injections`, before the precompile branch:

```rust
    // D2 (phase 4): the walk writes the digest it reaches over `leaf` and returns it — the leaf is
    // consumed. It must not alias what the walk still reads.
    let (lo, hi) = (b.addr_of(leaf.0), b.addr_of(leaf.0) + DIGEST_ELEMS as u64);
    let overlaps = |p: Ptr, n: u64| { let a = b.addr_of(p); a < hi && lo < a + n };
    assert!(!overlaps(siblings, (levels * DIGEST_ELEMS) as u64)
            && injections.iter().all(|inj| !overlaps(inj.rows, inj.n_cells as u64)),
            "the walk consumes its leaf (overwrites it with the digest it reaches): the leaf must not \
             alias the siblings or an injection's rows");
```

Add the same check against the hash scratch: `let st = b.hash_scratch(); overlaps(st, 16)` must be false. `hash_scratch()` is idempotent, so call it once. The `On` path becomes `let cur = leaf.0;` (no alloc, no copy in), the same loop, then `leaf` returned with no copy out. The `Off` path keeps its copy into `st`, ends with `b.copy_cells(leaf.0, 0, st, 0, DIGEST_ELEMS);`, and returns `leaf`. The callers in `rv32.rs` drop their `out` allocations and pass the returned digest to `assert_cap_eq`.

- [ ] **Step 4: Run the tests.** Run `cargo test --release -p recursion --test precompiles --test transcript`, which should pass, then `cargo test --release -p recursion --test verifier`. `the_off_replay_reproduces…` now fails on the digest only, because the Off walk writes into the leaf instead of an `out` cell and every later address shifts. Its acceptance half must still pass. Re-record the new digest in the assertion and extend the doc comment's history: `Phase 4's D2 re-recorded it (2026-10-09: the walk returns its leaf, no out cell, in both builds): c580415b…5e6c → <new8>…<new4>.`

- [ ] **Step 5: Run the targeted suite**, which should pass apart from the listed pin tests. **Measure** with the profile command and save the log as `docs/measurements/2026-10-09-span-profile-d2.log`. Expect ≈ 367 339; report the Δ against the band.

- [ ] **Step 6: Commit**

```bash
git add src/dsl/hash.rs src/programs/rv32.rs tests/transcript.rs tests/verifier.rs tests/precompiles.rs docs/measurements/2026-10-09-span-profile-d2.log
git commit -m "recursion: phase 4 D2 — the Merkle walk compresses over its leaf and returns it (no copy in or out); aliasing refused at build; Off-replay digest re-recorded; production <N> rows

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 4: B and B′, immediate-address `SPONGE` and `COMPRESS`

**Files:**
- Modify: `src/isa.rs` (`Op::b_is_register`: drop `Sponge`, `Compress`; update the opcode docs for 25 and 27)
- Modify: `src/tables/cpu.rs:122` (`Sels::B_REG`: drop `Op::Sponge`, `Op::Compress`; update the comments at lines ≈ 68 and 286 that say "SPONGE's source (and COMPRESS's sibling), `B0`" so they say the immediate)
- Modify: `src/emulator.rs` (the `Sponge` and `Compress` arms: `b_val[0] = instr.b`, with no `reg_b`)
- Modify: `src/dsl/builder.rs` (`sponge_absorb`, `compress_step`: emit `BRef::Imm(F::from_u64(self.addr_of(ptr)))` and stop calling `ptr_reg` for that operand)
- Modify: `tests/isa.rs:19` (assert COMPRESS's fourth word is **not** a register; same for SPONGE), `tests/cpu.rs:513,516` (`i(Op::Sponge, 0, 7, 96)`, `i(Op::Compress, 9, 7, 96)`), `tests/emulator.rs:280,298` (sibling immediate 80), `tests/common/mod.rs:656` (sibling immediate 80)
- Modify: `docs/00-recursion-vm.md` (the ISA table rows for `SPONGE` / `COMPRESS`; grep for them)
- Test: `tests/cheating.rs`, `tests/emulator.rs`, `tests/cpu.rs`
- Create: `docs/measurements/2026-10-09-span-profile-b.log`

**Interfaces:**
- Produces: the ISA meaning `SPONGE r0, ra, imm` (state at `regs[ra]`, source block at the absolute address `imm`) and `COMPRESS rd, ra, imm` (bit in `regs[rd]`, state at `regs[ra]`, sibling at `imm`). The cpu bus keys already read `B0`, which the immediate-form constraint now pins to `B`.

**Ruling recorded (spec §1.4's "range-checked as an address like LOAD/STORE's"):** `LOAD`/`STORE` have no decode-time address check. Their range proof is the cpu AIR's limbs, plus the emulator's `bounded`. The immediates get exactly that: group 2's limbs (`B0 + 3 < 2^24`) and the emulator's `AddressOutOfRange`. No new `DecodeError` variant.

- [ ] **Step 1: Write the failing tests.**

In `tests/emulator.rs`:

```rust
#[test]
fn sponge_and_compress_read_their_second_address_from_the_immediate() {
    // r8 holds an unrelated value: under the immediate form the address is the word, not a register.
    let p = Program { instrs: vec![
        i(Op::Faddi, 1, 0, 64), i(Op::Faddi, 8, 0, 5000), i(Op::Faddi, 3, 0, 1),
        i(Op::Sponge, 0, 1, 80),
        i(Op::Compress, 3, 1, 96),
        i(Op::Halt, 0, 0, 0),
    ], checkpoints: vec![], reduce_layout: vec![] };
    let ex = execute(&p, &[], 100).unwrap();
    let sp = ex.events.iter().find(|e| e.instr.op == Op::Sponge).unwrap();
    assert!(matches!(sp.perm.as_ref().unwrap().kind, PermKind::Sponge { src: 80 }));
    let cp = ex.events.iter().find(|e| e.instr.op == Op::Compress).unwrap();
    assert!(matches!(cp.perm.as_ref().unwrap().kind, PermKind::Compress { sib: 96, bit: true }));
}

#[test]
fn a_sponge_or_compress_immediate_past_the_address_space_is_refused_by_name() {
    let top = (1u64 << 24) - 2; // top cell = top + 3 >= 2^24
    for op in [Op::Sponge, Op::Compress] {
        let p = Program { instrs: vec![i(Op::Faddi, 1, 0, 64), i(op, 0, 1, top), i(Op::Halt, 0, 0, 0)],
                          checkpoints: vec![], reduce_layout: vec![] };
        assert!(matches!(execute(&p, &[], 100), Err(ExecError::AddressOutOfRange { pc: 1, .. })), "{op:?}");
    }
}
```

In `tests/cheating.rs` (honest proof, then a forged second address, then forged limbs):

```rust
/// Phase 4 B/B′: a program with one SPONGE and one COMPRESS at immediate addresses.
fn hash_setup() -> (Machine, Program, Traces) {
    let mut instrs = vec![i(Op::Faddi, 7, 0, 64), i(Op::Faddi, 9, 0, 1)];
    for k in 0..8 { instrs.push(i(Op::Faddi, 2, 0, 10 + k)); instrs.push(i(Op::Store, 2, 0, 96 + k)); }
    instrs.push(i(Op::Sponge, 0, 7, 96));       // SPONGE row
    instrs.push(i(Op::Compress, 9, 7, 100));    // COMPRESS row
    for k in 0..4 { instrs.push(i(Op::Load, 3, 7, k)); instrs.push(i(Op::Public, 0, 3, 0)); }
    instrs.push(i(Op::Halt, 0, 0, 0));
    let p = Program { instrs, checkpoints: vec![], reduce_layout: vec![] };
    let m = Machine::new(FriProfile::Test);
    let exec = execute(&p, &[], 10_000).unwrap();
    let t = build_traces(&p, &exec, Tier(8)).unwrap();
    (m, p, t)
}

fn row_of(p: &Program, op: Op) -> usize { p.instrs.iter().position(|x| x.op == op).unwrap() }

#[test]
fn honest_immediate_address_hash_traces_pass() {
    let (m, p, t) = hash_setup();
    prove_and_verify(&m, &p, &t).unwrap();
}

#[test]
fn a_sponge_source_moved_off_its_immediate_is_rejected() {
    let (m, p, mut t) = hash_setup();
    let w = cpu::col::WIDTH;
    t.cpu.values[row_of(&p, Op::Sponge) * w + cpu::col::B0] += F::from_u64(4); // another block
    assert!(rejects(|| prove_and_verify(&m, &p, &t)));
}

#[test]
fn a_compress_sibling_moved_off_its_immediate_is_rejected() {
    let (m, p, mut t) = hash_setup();
    let w = cpu::col::WIDTH;
    t.cpu.values[row_of(&p, Op::Compress) * w + cpu::col::B0] -= F::from_u64(4);
    assert!(rejects(|| prove_and_verify(&m, &p, &t)));
}

#[test]
fn a_forged_second_pointer_limb_on_an_immediate_row_is_rejected() {
    let (m, p, mut t) = hash_setup();
    let w = cpu::col::WIDTH;
    t.cpu.values[row_of(&p, Op::Sponge) * w + cpu::col::G2LIMB0] += F::ONE;
    assert!(rejects(|| prove_and_verify(&m, &p, &t)));
}
```

In `tests/cpu.rs` (no `REG` read for the second address):

```rust
#[test]
fn sponge_and_compress_rows_send_no_rb_register_read() {
    let p = multi_cell_program();
    let tape: Vec<F> = (1..=8).map(F::from_u64).collect();
    let exec = recursion::emulator::execute(&p, &tape, 1000).unwrap();
    let regs = recursion::tables::cpu::register_accesses(&exec.events);
    // Row 7 is the SPONGE, row 10 the COMPRESS: their clk·16 + TS_RB slot (= 2) carries no read.
    for row in [7u32, 10] {
        let clk = exec.events[row as usize].clk;
        assert!(regs.iter().all(|a| a.ts != clk * 16 + 2), "row {row} still reads rb");
    }
}
```

Check `TS_RB`'s value in `src/tables/cpu.rs` and use it. If it is private, compare against the count of register accesses for the row before the change (`ra` read, plus `rd` read for COMPRESS: 1 and 2).

- [ ] **Step 2: Run them and see them fail.** Run `cargo test --release -p recursion --test emulator --test cheating --test cpu --test isa`. Expected: the emulator still reads `regs[b]` (wrong `src` / `sib`, or a `Decode` register error for 80/96 ≥ 32); `honest_immediate_address_hash_traces_pass` fails to decode; the `rb` test finds a read.

- [ ] **Step 3: Implement.**
  - `src/isa.rs`: `b_is_register` → `matches!(self, Op::Fadd | Op::Fsub | Op::Fmul | Op::Eadd | Op::Esub | Op::Emul | Op::Emulf)`, with a doc sentence: "`SPONGE` and `COMPRESS` (phase 4) take their second address as an absolute immediate."
  - `src/tables/cpu.rs`: `B_REG` loses `Op::Sponge, Op::Compress`. Do not touch the constraints: `is_b_reg` now leaves both rows in the immediate form (`B0 = B`, `B1 = 0`), and the bus keys and group-2 limbs already read `B0`.
  - `src/emulator.rs`: in both arms, delete the `reg_b` line and set `b_val[0] = instr.b;` (the event's `b_val` default for non-register ops is already `[instr.b, 0]`, so assigning it explicitly is for readability; keep the `bounded` checks).
  - `src/dsl/builder.rs`:

```rust
    pub fn sponge_absorb(&mut self, state: Ptr, src: Ptr) {
        self.begin();
        let ra = self.ptr_reg(state);
        // Phase 4 B′: the source block's address is a compile-time constant — an immediate.
        let at = F::from_u64(self.addr_of(src));
        self.emit(Op::Sponge, RRef::Raw(0), ra, BRef::Imm(at));
        self.stats.perms += 1;
    }

    pub fn compress_step(&mut self, state: Ptr, sib: Ptr, bit: Felt) {
        self.begin();
        let ra = self.ptr_reg(state);
        // Phase 4 B: the sibling's address is a compile-time constant — an immediate.
        let at = F::from_u64(self.addr_of(sib));
        let rd = self.materialise(bit.0);
        self.emit(Op::Compress, rd, ra, BRef::Imm(at));
        self.stats.perms += 1;
    }
```

  Keep the existing doc comments above both functions and update them to say "immediate".
  - Update the hand-written programs in `tests/cpu.rs`, `tests/emulator.rs` and `tests/common/mod.rs` to immediates, and `tests/isa.rs`'s assertions (`!Op::Compress.b_is_register()`, plus the same for `Sponge`, with messages saying it is now the absolute address).
  - `docs/00-recursion-vm.md`: the two ISA rows, with a dated line "phase 4: the fourth word is the absolute address".

- [ ] **Step 4: Run the tests and see them pass.** Run `cargo test --release -p recursion --test emulator --test cheating --test cpu --test isa --test precompiles`. Then run the targeted suite, which should pass apart from the listed pin tests. `tests/verifier_key.rs` caps are expected to move (the AIR's `B_REG` changed); Task 5 re-records them.

- [ ] **Step 5: Measure** with the profile command and save the log as `docs/measurements/2026-10-09-span-profile-b.log`. Expect ≈ 317 315; report the Δ against the band and the `reg_accesses` count (the spike's software-only figure was 817 303; this cut removes one more read for each `SPONGE` and `COMPRESS`).

- [ ] **Step 6: Commit**

```bash
git add src/isa.rs src/tables/cpu.rs src/emulator.rs src/dsl/builder.rs tests/isa.rs tests/cpu.rs tests/emulator.rs tests/common/mod.rs tests/cheating.rs docs/00-recursion-vm.md docs/measurements/2026-10-09-span-profile-b.log
git commit -m "recursion: phase 4 B/B′ — SPONGE's source and COMPRESS's sibling as absolute immediates (dropped from b_is_register and B_REG; the existing immediate form binds B0 = B, B1 = 0; no new column); forgeries refused; production <N> rows

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 5: Re-pin and the full suite

**Files (each re-recorded from a measured run, never from the spike):**
- `src/programs/verify_rv32.digest` (`tests/exit.rs` checks it against a rebuild)
- `tests/pins.json`: every field, including the `aggregate_test_n{1,2,3}_*` and `phase3_attribution` entries. Edit by hand from measured values; `common::pins()` regenerates only the first five fields.
- `tests/exit.rs:380` (the `585_686` literal, with its history message extended: `… after phase 4 (<N>); 585 686 after phase 3's Cut F; …`) and any tier assertion there
- `tests/aggregate.rs`: `LOOP_OVERHEAD` (274 → measured), `N3_ROWS`, tier assertions, and the `#[ignore]` strings' tier/row/projection text for the production N=1/2/3 and B3 emulation tests
- `tests/self_verify.rs`: the self-verifier digest (`b42ae772…`), the toy and busy `CycleReport` tuples, the phase-5 constants (7933/8213) if they move
- `tests/verifier_key.rs`: the two caps (`4e14ef4f…`, `5205f8d6…`)
- `tests/memprofile.rs`: tier assertions and the `#[ignore]` text (the exit twin is projected to tier 17)
- `tests/dsl-sample.digest`, if Task 2 did not already record it
- Any other assertion the full suite names

**Interfaces:** none produced. This task only re-records pins.

- [ ] **Step 1: Run the full suite** with `--no-fail-fast`:

```bash
cargo test --release --no-fail-fast -- --skip a_one_proof_aggregate_round_trips 2>&1 | tee /tmp/phase4-suite-1.log | grep -E '^test .* FAILED|^test result|panicked' | head -80
```

- [ ] **Step 2: Classify every failure.** Each must be a pin (digest, row count, tier, cap, cycle report) moved by Tasks 1–4. Anything else, such as a refused honest proof, a wrong refusal step in a tamper table, or a panic in the replay, is a defect: stop and report BLOCKED with the failing test's output.

- [ ] **Step 3: Re-record each pin** from the failure's `left`/`right`. Extend each pin's history comment in place in the file's existing style: one clause `Phase 4 (2026-10-09, the Merkle spans) re-recorded it: <old> → <new>.`. Tier assertions take the tier the measured rows give (`tier = ceil(log2(rows + 1))`, as `RvmTier` computes). In `tests/aggregate.rs`, `LOOP_OVERHEAD` is the measured `n1_rows − single_rows`.

- [ ] **Step 4: Assert the invariants did not move.** These must pass unchanged, with no pin edits: `inner_vk_digest`'s pin, the interface digest vectors, `tests/security.rs`, `tests/quotient_layout.rs`, `tests/machine.rs`'s `RvmFri` pin, and `the_aggregate_program_digest_is_unchanged_by_rvm_constraint_fixes` (if it fails, read it: if it pins the aggregate digest, re-record it as a phase-4 move and say so).

- [ ] **Step 5: Re-run the full suite** (same command, log to `/tmp/phase4-suite-2.log`). Expected: 0 failed. Record the pass/ignored counts (the rate-¼ end was 298 passed, 20 ignored) plus the new tests from Tasks 1–4.

- [ ] **Step 6: Run the cfg-gated backends** the way `docs/07` §6 does: `cargo test --release -p recursion --features reference-backend --test backend` and `--features mock-cuda --test backend`. Both must pass.

- [ ] **Step 7: Commit**

```bash
git add -A src/programs/verify_rv32.digest tests/
git commit -m "recursion: phase 4 re-pin — program digests, rVM verifier key caps, pins.json, LOOP_OVERHEAD, N3_ROWS, tiers (one inner verification <N> rows, tier 19); suite <P> passed / 0 failed / <I> ignored

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 6: Measurement and `docs/08`

**Files:**
- Create: `docs/measurements/2026-10-09-twin-before.log`, `-twin-after.log`, `-tier16-before.log`, `-tier16-after.log`, `-aggregate-n2.log`, `-prod-n2-emulate.log`, `-prod-n3-emulate.log`, and `-aggregate-n3.log` if run
- Create: `recursion/docs/08-phase4-spans.md`
- Modify: `recursion/docs/06-phase3-fold-reduce.md` §7 item 1 (a pointer: "done in phase 4, `docs/08`"), `recursion/docs/01-*.md` (a one-line pointer next to the other phase docs; grep for where `docs/07` is linked and add `docs/08` beside it)

**Interfaces:** none.

- [ ] **Step 1: The "before" runs.** These need the base tree. Create a throwaway worktree at the base: `git -C ~/rand-worktrees/circuits-phase4 worktree add /tmp/phase4-base 71e1a04`. If its `target/` would need a full rebuild and disk is short, check `df -h ~` first (keep ≥ 40 GB free). Run there:

```bash
cd /tmp/phase4-base/recursion
RAYON_NUM_THREADS=16 cargo test --release --features parallel --test memprofile -- --ignored --nocapture tier19_exit_twin 2>&1 | tee ~/rand-worktrees/circuits-phase4/recursion/docs/measurements/2026-10-09-twin-before.log
RAYON_NUM_THREADS=16 cargo test --release --features parallel --test memprofile -- --ignored --nocapture tier16_synthetic_threads 2>&1 | tee ~/rand-worktrees/circuits-phase4/recursion/docs/measurements/2026-10-09-tier16-before.log
```

Run one heavy job at a time. Then `git -C ~/rand-worktrees/circuits-phase4 worktree remove /tmp/phase4-base`.

- [ ] **Step 2: The "after" runs** on the branch: the same two commands from `~/rand-worktrees/circuits-phase4/recursion` into `-after.log`. Then:

```bash
RAYON_NUM_THREADS=16 cargo test --release --features parallel --test aggregate -- --ignored --nocapture two_test_profile_bundle_proofs_aggregate_and_verify_natively 2>&1 | tee docs/measurements/2026-10-09-aggregate-n2.log
cargo test --release --test aggregate -- --ignored --nocapture production_n2_aggregate_emulates_within_bounds 2>&1 | tee docs/measurements/2026-10-09-prod-n2-emulate.log
cargo test --release --test aggregate -- --ignored --nocapture production_n3_aggregate_emulates_within_bounds 2>&1 | tee docs/measurements/2026-10-09-prod-n3-emulate.log
```

Run the test N=3 twin (`twin_three_test_profile_bundle_proofs_aggregate_and_verify_natively`) only if the N=2 run's peak live heap is ≤ 30 GB. It is watchdog-guarded; record it as "not run (reason)" otherwise. The production N=1 proof is not run on this box.

- [ ] **Step 3: Write `docs/08-phase4-spans.md`**, in `docs/07`'s style and section order:
  1. *Why*: phase 3's 585 686 rows, the tier-19 gate, the two spans (`input_root` 248 151, `commit_root` 120 640 at baseline).
  2. *Anatomy*: the §0.1 list from the spec, with the baseline log's measured numbers.
  3. *The four cuts*: what each does, its soundness argument (D1's boolean bits and the contiguous caps; A's three rules plus the mutable and pre-loop guards; D2's aliasing assertion; B/B′'s program-word immediate and the limbs), and a table of expected Δ, measured Δ and band verdict from Tasks 1–4's logs.
  4. *Measured*: a before/after table like `docs/07` §3 (twin, tier-16 synthetic: peak live heap, prove wall, verify, proof bytes; test N=2; production N=2/N=3 emulated rows and tiers; `reg_accesses`; REG table height).
  5. *N-economics*: N=1/2/3 production rows → tiers; the node's `admitted_tiers` and reduce N ceiling re-derived (stated as the recommendation the fullnode follow-through applies).
  6. *What moved*, with the re-record list from Task 5. *What did not*, from Global Constraints.
  7. *Testing*: the new tests by name, and the suite counts.
  8. *Out of scope*: spec §7.
  9. *Conclusion*.
  Every memory figure comes from the heap profiler logs; no RSS.

- [ ] **Step 4: Add the pointers** in `docs/06` §7 item 1 and `docs/01`.

- [ ] **Step 5: Commit**

```bash
git add docs/08-phase4-spans.md docs/06-phase3-fold-reduce.md docs/01-*.md docs/measurements/2026-10-09-*.log
git commit -m "recursion docs: docs/08 — phase 4, the Merkle spans: <N> rows (tier 19), the exit twin <a> → <b> GB live, measured bands, N-economics

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

(Paths are relative to `recursion/`. Quote the `docs/01-*.md` glob if the shell complains, or name the file.)

---

## After the plan

The fullnode re-vendor (`deploy/sync-zkvm.sh`, `CIRCUITS_PIN`, `aggregate_program_digest` re-pin, `admitted_tiers` from `docs/08` §5) follows as its own task after the branch is merged and pushed, as with rate ¼. Merging and pushing are the operator's calls.
