# Rand zkVM — the public input segment (constraint set 6) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give the machine a second, unsalted input space — the **public segment** — whose digest `H_PUB` is published as eight new public values and recomputed natively by the verifier, so that a guest may bind data (an ELF, a codehash, calldata) the chain can see without hashing it in-circuit; and use it to take the sBPF guest's ~1.05 M cycles of redundant SHA-256 off the exit test.

**Architecture:** A new witness table `public` mirrors `input` column for column (`IDX, WORD, IS_REAL, MULT_READ`, proof-declared height) and provides `(IDX, WORD)` on two split buses, `PUBLIC_DIGEST` (count `IS_REAL`) and `PUBLIC_READ` (count `IS_REAL * MULT_READ`). A third cpu digest region, `IS_PUBDIGEST`, sits after the `IS_INDIGEST` region and computes `H_PUB = Poseidon2(domain PUB, n_pub; words)` with **no salt**, pinned to `pv::PUB0..PUB7`. A new syscall `SYS_READ_PUBLIC = 6` reads the segment. `Machine::verify` is unchanged; a new `Machine::verify_public(hc, public_words, proof)` additionally recomputes the digest natively and compares. The sBPF guest then reads its ELF from the public segment, drops `program_hash` entirely, and hashes a canonical unpadded encoding of the instruction instead of the 98 %-zero aligned region.

**Tech Stack:** Rust 1.98.1, Plonky3 0.7 (unchanged), `riscv32im-unknown-none-elf` + `llvm-tools`, `guest-sdk`, `sbpf-core` (no_std, `#![forbid(unsafe_code)]`), `solana-sbpf = "=0.11.1"` and `sha2 = "=0.10.9"` as host oracles. No new dependency.

**Spec:** `docs/superpowers/specs/2026-09-11-zkvm-m4-design.md` **§9** (the decision record for everything below), and §5.1 item 8 (why option B, and what §9.5 corrects in it). Background: `research/docs/04-guests.md` ("The `sbpf` guest"), `research/docs/02-tables-and-buses.md` (the `input` table section — the template), `research/docs/03-privacy.md`, `docs/superpowers/plans/2026-09-11-zkvm-m4-1.md` (how the `input` table was planned; its review-round-1 C1 reasoning is reused verbatim), `docs/superpowers/plans/2026-09-12-zkvm-m4-4.md` (the format this plan mirrors; its Task 6 is the exit test this plan unblocks).

## Global Constraints

- Every cargo command is `cargo +1.98.1 ...` run from `research/`. Guest crates (`guest-sdk`, `guests-compiled/*`) are their own workspace roots.
- **At most one proving suite may run on this machine at a time.** The research suite peaks at ~22.4 GiB and the machine has 48 GB. **Before any step that proves** (anything running `tests/e2e.rs`, `tests/cheating.rs`, `tests/bundle.rs`, `tests/viewing.rs`, `tests/zk.rs`, `tests/tables.rs`, or the full suite), run `ps -eo rss= | awk '$1>8000000'` and proceed only if it prints nothing. If it prints a line, another proving job is live — wait and re-check; do not start a second one.
- **Never run `cargo test` unqualified while another session is proving.** Prefer the narrowest `--test <file> <name>` selector that covers the step.
- **Invariant 1** (`research/AGENTS.md`): every bus message column is constrained on every row kind that sends it. **Invariant 2**: a bus count is forced to zero wherever the message columns are unconstrained. Both apply to the `public` table's padding rows (`WORD` and `MULT_READ` pinned to 0) and to every new cpu row kind.
- **Degree cap 8.** `tests/tables.rs::alu_max_constraint_degree_is_pinned` now pins a **nine**-entry bare shape (`klh = slh = 0`) and an **eleven**-entry full shape. `public` is expected at degree 2 (`input`'s); `cpu` must stay at 8. Any measured value that differs is written down in the test and in `docs/02-tables-and-buses.md` rather than "fixed".
- **Bus catalogue**: fourteen → **sixteen**. `bus::PUBLIC_DIGEST` (message `[idx, word]`, count `IS_REAL`), `bus::PUBLIC_READ` (message `[idx, word]`, count `IS_REAL * MULT_READ`). The split is mandatory — spec §9.8, M4.1 review round 1 C1.
- **Chip order**: `Chip::Public` appended **last** in `machine::chips()`, after `Sha256`; its `log_ext_degrees` entry after sha256's; `Traces::as_slice` pushes it last. Its index is therefore `8 + (klh != 0) + (slh != 0)`. `i == 1` (`Cpu`, the public-values slot) and `i == 2` (`Memory`, indexed directly by `tests/cheating.rs`) must not move.
- **Heights**: `public_log_height(n) = pad_height(n + 1, MIN_HEIGHT).trailing_zeros() as u8`, `MIN_HEIGHT = 4`, `MIN_LOG_HEIGHT = 2`, `MAX_LOG_HEIGHT = 20` — `tables::input`'s rule and constants exactly. `Proof.public_log_height: u8`; `check_declared_heights` bounds it to `[MIN_LOG_HEIGHT, MAX_LOG_HEIGHT]` **before** anything is sized from it. There is no "0 means absent" value: the table is mandatory.
- **Effective cap on `n_pub` is 65 535**, not `2^20`: `HASH_LEFT` is 16-bit in the cpu AIR's `LEFT0..1` byte limbs, exactly as for `n_in` and the program length. `build_traces_salted` returns `ProveError::PublicTooLong { len }` above it.
- **ABI**: `SYS_READ_PUBLIC = 6`, `a0 = idx` in, `a0 = word` out, no second argument, one cpu row. `idx >= n_pub` is `ExecError::PublicIndex(idx)` from `emulator::execute` — the run yields no trace at all, mirroring `ExecError::InputIndex`. (Spec §9.2 records that this is what "an exceptional halt like an out-of-range `READ_INPUT`" means in this machine.)
- **Digest**: `H_PUB = Poseidon2(domain PUB, n_pub; words)`, capacity header `[PUB_DOMAIN, n_pub, 0]`, **no salt block**, `public_digest_row_count(n) = n.div_ceil(4).max(1)` (`program_digest`'s rule, not `input_digest`'s — there is no salt row to guarantee a block). `notes::domain::PUB = 15`.
- **Public values**: `pv::PUB0 = pv::IN0 + 8 = 26`, `pv::NUM` 26 → **34**.
- **Verifier key** becomes a 6-tuple `(tier, program_log_height, input_log_height, keccak_log_height, sha256_log_height, public_log_height)`. **The fullnode is not re-vendored by this plan.** `deploy/sync-zkvm.sh` (in the fullnode repo) patches on an anchor that is the exact `verifier_key` signature line and also tracks `pv::NUM`; both move here, and updating that script is the vendoring's job, noted in the docs.
- **This is constraint set 6.** Proofs from set 5 no longer verify.
- **Every existing guest keeps proving with `public = &[]`** and every existing expected-output assertion is unchanged. A call-site-only diff is the bar for every test outside the new ones.
- **Docs carry measured numbers**: the `public` table's width and degree, the sBPF guest's program words / private input words / public words / cycles / compressions / tier / `sha256_log_height` / `mem_log_height` / proof size, and test counts in `README.md`, `AGENTS.md` and `docs/05-roadmap.md`.
- Commit style: `research: public — …`, `research: sbpf — …`, `research: docs — …`. One logical change per commit; docs ride with the change they describe.

## Rulings made in this plan

(The design rulings are the spec's — §9.8. These are the ones this plan adds on top of them.)

| ruling | why | cost if wrong |
|---|---|---|
| `pv::PUB0..7` and the host-side `H_PUB` land in Task 1; the in-circuit **binding** lands in Task 2 | Task 1 is host-level and testable on its own (`public_digest` against `sponge_hash`, the syscall against the emulator); a single task that also rewrote the cpu digest region would have no reviewable middle | between Task 1 and Task 2 `pv::PUB0..7` is a declared value bound to nothing — Task 2's cheating tests are what close it, and Task 3 is what proves they close it. **Do not ship Task 1 alone.** |
| the last indigest row gains `IPOUT0..7` in Task 2, retargeting its `POSEIDON2` `state_out` and its `IHVL` pin off `n(HS0 + j)` | the row after it is now the first pubdigest row, whose `n(HS0..7)` carries `H_PUB`'s header seed; this is M4.1's `DPOUT0..7` collision one region later, and it makes an **honest** witness unsatisfiable if missed | the whole task fails at `honest_traces_pass` with a constraint panic and no hint; budget for it up front |
| new cpu columns are appended at the end of `col`, never slotted next to their relatives | column indices are load-bearing for the vendored fullnode at re-vendoring time; `SYS_KECCAK` and `SYS_SHA256` set this precedent and say so | a re-vendoring reads the wrong columns |
| Task 4 rewrites `sbpf-core`'s ABI and rebuilds the guest binary in one task | the guest binary is only meaningful against the library it was built from; splitting them leaves a committed `.bin` that does not match `sbpf-core`, which has happened before (`research/AGENTS.md`, the `make install` note) | a test measuring the previous binary |
| the exit test is un-ignored only if measured tier ≤ 18 **and** the proof completes on this 48 GB machine | spec §9.5 projects ~699 K cycles = tier 20; an honest `#[ignore]` with a fresh measurement beats an un-ignored test that cannot run | the ignore message and `docs/04-guests.md` carry the new numbers, as M4.3's tier-18 EVM proof already does |

## File structure

```
research/
  src/notes.rs             [Task 1] domain::PUB = 15
  src/hash.rs              [Task 1] public_digest, public_digest_rows, public_digest_row_count
  src/isa.rs               [Task 1] SYS_READ_PUBLIC = 6
  src/emulator.rs          [Task 1] Syscall::ReadPublic, ExecError::PublicIndex, execute(.., public, ..)
  src/asm.rs               [Task 1] ops::read_public(idx)
  src/tables/cpu.rs        [Task 1] pv::PUB0, pv::NUM = 34, public_values(.., hpub)
                           [Task 2] SYS_READ_PUB, IS_PUBDIGEST, PUBDIGEST_LAST, IPOUT0..7,
                                    PHVL0..31, PHIMAX0..3, PINV0..3, fill_public_digest_rows
  src/machine.rs           [Task 1] public threaded through prove/prove_salted/prove_with/prove_on/
                                    build_traces/build_traces_salted
                           [Task 2] Chip::Public, Traces.public/public_log_height,
                                    Proof.public_log_height, log_ext_degrees, verifier_key 6-tuple,
                                    check_declared_heights, max_constraint_degrees, verify_public,
                                    ProveError::{PublicTooLong, PublicTooLarge},
                                    VerifyError::PublicHeight
  src/tables/mod.rs        [Task 2] pub mod public; bus::PUBLIC_DIGEST, bus::PUBLIC_READ
  src/tables/public.rs     [Task 2, new] PublicAir, col, public_log_height, read_counts, public_trace
  src/guests.rs            [Task 1] every call site gains `&[]`; [Task 2] public_echo() demo guest
  src/sbpf.rs              [Task 4] SbpfCall::public_words(), canonical_input_hash host twin,
                                    expected() over two segments
  tests/emulator.rs        [Task 1] SYS_READ_PUBLIC semantics
  tests/asm.rs             [Task 1] ops::read_public
  tests/tables.rs          [Task 2] public table shape, degree pin (9 and 11 entries)
  tests/e2e.rs             [Task 2] public_echo proves and verify_public checks the words
                           [Task 5] the sBPF exit test, re-measured
  tests/cheating.rs        [Task 3] nine public-segment attacks
  tests/sbpf_abi.rs        [Task 4] canonical input_hash, two-segment decode, the SPL fixture
  docs/01-isa.md, 02-tables-and-buses.md, 03-privacy.md, 04-guests.md, 05-roadmap.md,
  README.md, AGENTS.md     [Task 5]
guest-sdk/src/lib.rs       [Task 1] read_public(idx)
guests-compiled/
  sbpf-core/src/abi.rs     [Task 4] two cursors, canonical_input_hash, public_output without
                                    program_hash, run_call/run_call_with over both segments
  sbpf/src/main.rs         [Task 4] reads the ELF with read_public
  bin/sbpf.bin (+.sha256)  [Task 4] rebuilt
```

---

### Task 1: Domain, digest, syscall, SDK, and the `public` parameter

**Files:**
- Modify: `research/src/notes.rs`, `research/src/hash.rs`, `research/src/isa.rs`, `research/src/emulator.rs`, `research/src/asm.rs`, `research/src/tables/cpu.rs` (the `pv` module and `public_values` only), `research/src/machine.rs` (signatures only), `research/src/guests.rs`, `guest-sdk/src/lib.rs`
- Test: `research/tests/emulator.rs`, `research/tests/asm.rs`, and a new `#[cfg(test)]` block in `research/src/hash.rs`'s own test file if one exists — otherwise the two test files above plus `research/tests/isa.rs`

**Interfaces:**
- Consumes: `hash::{DigestBlock, permute_state, split_digest}`, `notes::domain`, `isa::{SYS_READ_INPUT, SYS_HALT}`, `emulator::{Syscall, ExecError, execute}` as they stand.
- Produces:

```rust
// research/src/notes.rs
pub const PUB: u32 = 15;                                   // in mod domain

// research/src/hash.rs
pub fn public_digest(public: &[u32]) -> [u32; 8];
pub fn public_digest_rows(public: &[u32]) -> Vec<DigestBlock>;
pub fn public_digest_row_count(n: usize) -> usize;         // n.div_ceil(4).max(1)

// research/src/isa.rs
pub const SYS_READ_PUBLIC: u32 = 6;

// research/src/emulator.rs
pub enum Syscall { /* … */ ReadPublic { idx: u32, word: u32 } }
pub enum ExecError { /* … */ PublicIndex(u32) }
pub fn execute(program: &Program, inputs: &[u32], public: &[u32], max_cycles: usize) -> Result<Execution, ExecError>;

// research/src/asm.rs, in mod ops
pub fn read_public(idx: u32) -> Vec<Instr>;

// research/src/tables/cpu.rs, in mod pv
pub const PUB0: usize = IN0 + 8;                           // 26
pub const NUM: usize = PUB0 + 8;                           // 34

// research/src/machine.rs — `public: &[u32]` added to every one of these
pub fn build_traces(program: &Program, inputs: &[u32], public: &[u32], exec: &Execution, tier: Tier) -> Result<Traces, ProveError>;
pub fn build_traces_salted(program: &Program, inputs: &[u32], public: &[u32], salt: [u32; 4], exec: &Execution, tier: Tier) -> Result<Traces, ProveError>;
impl Machine {
    pub fn prove(&self, program: &Program, inputs: &[u32], public: &[u32], tier: Option<Tier>) -> Result<(Proof, Execution), ProveError>;
    pub fn prove_salted(&self, program: &Program, inputs: &[u32], public: &[u32], salt: [u32; 4], tier: Option<Tier>) -> Result<(Proof, Execution), ProveError>;
    pub fn prove_with(&self, backend: Backend, program: &Program, inputs: &[u32], public: &[u32], tier: Option<Tier>) -> Result<(Proof, Execution), ProveError>;
}

// guest-sdk/src/lib.rs
pub fn read_public(idx: u32) -> u32;
```

- [ ] **Step 1: Write the failing tests**

Append to `research/tests/emulator.rs`:

```rust
#[test]
fn read_public_returns_the_public_word_and_is_bound_by_its_own_length() {
    use rand_zkvm::asm::{ops::*, Assembler};
    use rand_zkvm::emulator::{execute, ExecError, Syscall};
    let mut a = Assembler::new(0);
    a.extend(read_public(1));
    a.push(mv(5, REG_A0));
    a.extend(read_input(0));
    a.push(add(6, 5, REG_A0));
    a.extend(write_output(0, 6));
    a.extend(halt());
    let p = a.assemble();

    let e = execute(&p, &[100], &[7, 11], 10_000).unwrap();
    assert_eq!(e.outputs[0], 111, "public[1] + input[0]");
    assert!(
        e.events.iter().any(|ev| matches!(ev.sys, Some(Syscall::ReadPublic { idx: 1, word: 11 }))),
        "the read must show up as a ReadPublic event"
    );

    // Out of range is refused exactly as READ_INPUT's is: an ExecError, no trace at all.
    assert!(matches!(execute(&p, &[100], &[7], 10_000), Err(ExecError::PublicIndex(1))));
    assert!(matches!(execute(&p, &[100], &[], 10_000), Err(ExecError::PublicIndex(1))));
}

#[test]
fn the_two_segments_are_independent_spaces() {
    use rand_zkvm::asm::{ops::*, Assembler};
    use rand_zkvm::emulator::execute;
    let mut a = Assembler::new(0);
    a.extend(read_input(0));
    a.push(mv(5, REG_A0));
    a.extend(read_public(0));
    a.push(sub(6, 5, REG_A0));
    a.extend(write_output(0, 6));
    a.extend(halt());
    let p = a.assemble();
    // Same index, different spaces, different words.
    assert_eq!(execute(&p, &[900], &[400], 10_000).unwrap().outputs[0], 500);
}
```

Append to `research/tests/isa.rs` (or wherever the `hash` module's host tests live — grep for `input_digest` first and put these beside them):

```rust
#[test]
fn public_digest_is_the_unsalted_twin_of_the_program_digest() {
    use rand_zkvm::hash::{public_digest, public_digest_row_count, public_digest_rows};
    // Header-only: one permutation even for an empty segment, so H_PUB is never the all-zero digest.
    assert_eq!(public_digest_row_count(0), 1);
    assert_eq!(public_digest_rows(&[]).len(), 1);
    assert_ne!(public_digest(&[]), [0u32; 8]);
    // One block per four words, ceil.
    assert_eq!(public_digest_row_count(1), 1);
    assert_eq!(public_digest_row_count(4), 1);
    assert_eq!(public_digest_row_count(5), 2);
    // Unsalted: a pure function of the words. Two calls agree; H_IN's does not (it takes a salt).
    assert_eq!(public_digest(&[1, 2, 3]), public_digest(&[1, 2, 3]));
    // Length is in the capacity header, so trailing zeros are not a collision.
    assert_ne!(public_digest(&[1, 2, 3]), public_digest(&[1, 2, 3, 0]));
    // The domain separates it from H_IN's own space and from hc's.
    assert_ne!(public_digest(&[1, 2, 3, 4]), rand_zkvm::hash::input_digest([0; 4], &[1, 2, 3, 4]));
    // And the chain of blocks is the same overwrite-mode chain the other two digests use.
    let blocks = public_digest_rows(&[1, 2, 3, 4, 5]);
    assert_eq!(blocks.len(), 2);
    assert_eq!(blocks[0].left_before, 5);
    assert_eq!(blocks[1].left_before, 1);
    assert_eq!(blocks[1].active, [true, false, false, false]);
    assert_eq!(rand_zkvm::hash::split_digest([blocks[1].state_out[0], blocks[1].state_out[1], blocks[1].state_out[2], blocks[1].state_out[3]]), public_digest(&[1, 2, 3, 4, 5]));
}
```

Append to `research/tests/asm.rs`:

```rust
#[test]
fn ops_read_public_assembles_to_a7_six_and_a0_idx() {
    use rand_zkvm::asm::{ops::read_public, Assembler};
    let mut a = Assembler::new(0);
    a.extend(read_public(9));
    a.extend(rand_zkvm::asm::ops::halt());
    let p = a.assemble();
    let e = rand_zkvm::emulator::execute(&p, &[], &[0, 0, 0, 0, 0, 0, 0, 0, 0, 77], 100).unwrap();
    assert!(e.events.iter().any(|ev| matches!(ev.sys, Some(rand_zkvm::emulator::Syscall::ReadPublic { idx: 9, word: 77 }))));
}
```

- [ ] **Step 2: Run them and confirm they fail**

Run: `cargo +1.98.1 test --test emulator read_public --test asm read_public`
Expected: FAIL to compile — `read_public` is not a function, `execute` takes 3 arguments, `Syscall::ReadPublic` does not exist.

- [ ] **Step 3: The domain and the digest**

`research/src/notes.rs`, in `mod domain`, after `SBPF_OUT`:

```rust
    /// The public input segment's commitment (`hash::public_digest`), sealing the unsalted
    /// words `SYS_READ_PUBLIC` draws from — the capacity-lane header `[PUB, n_pub, 0]` seeded
    /// into the very first pubdigest-row permutation. `IN`'s header shape exactly, minus the
    /// salt block: this digest is meant to be recomputed by a verifier who holds the words
    /// (`Machine::verify_public`), which is precisely what a salted `H_IN` cannot support.
    pub const PUB: u32 = 15;
```

`research/src/hash.rs`, after `input_digest_row_count`:

```rust
/// H_PUB: the in-circuit commitment to the guest's **public** input segment — what
/// `tables::cpu`'s `IS_PUBDIGEST` rows compute and `pv::PUB0..PUB7` publish.
///
/// `input_digest` without the salt, which is the entire point: the words are published with the
/// transaction and `Machine::verify_public` recomputes this natively and compares. With no salt
/// block there is nothing guaranteeing a permutation at `n_pub == 0`, so this uses
/// `program_digest`'s `max(1, ⌈n/4⌉)` rule rather than `input_digest`'s — a header-only block —
/// and `public_digest(&[])` is therefore a fixed, non-zero value rather than the all-zero digest.
pub fn public_digest(public: &[u32]) -> [u32; 8] {
    let blocks = public_digest_rows(public);
    let state = blocks.last().expect("public_digest_rows always returns at least the header block").state_out;
    split_digest([state[0], state[1], state[2], state[3]])
}

/// One `tables::cpu` `IS_PUBDIGEST` row's worth of absorb data — `program_digest_rows` with
/// `domain::PUB` and `[PUB, n_pub, 0]` in the capacity lanes (no `base_pc` analogue for a flat
/// vector, exactly as `input_digest_rows` has none). `idx` numbers the rows from 0, matching
/// `tables::cpu`'s own `HASH_IDX` chain for the region.
pub fn public_digest_rows(public: &[u32]) -> Vec<DigestBlock> {
    let mut state = [Val::ZERO; 8];
    state[4] = Val::from_u32(crate::notes::domain::PUB);
    state[5] = Val::from_u32(public.len() as u32);
    // state[6] stays 0 — the header is [PUB_DOMAIN, n_pub, 0].
    let n = public.len();
    let rows = n.div_ceil(4).max(1);
    let mut out = Vec::with_capacity(rows);
    for i in 0..rows {
        let state_in = state;
        let mut block_words = [0u32; 4];
        let mut active = [false; 4];
        let mut merged = state;
        for k in 0..4 {
            let idx = i * 4 + k;
            if idx < n {
                block_words[k] = public[idx];
                active[k] = true;
                merged[k] = Val::from_u32(public[idx]);
            }
        }
        let left_before = (n - (i * 4).min(n)) as u32;
        state = permute_state(merged);
        out.push(DigestBlock { idx: i as u32, left_before, words: block_words, active, state_in, state_out: state });
    }
    out
}

/// `max(1, ⌈n/4⌉)` — the number of cpu-table `IS_PUBDIGEST` rows `H_PUB` costs, without
/// building the `Vec` (used by `build_traces_salted`'s cycle-budget check).
pub fn public_digest_row_count(n: usize) -> usize { n.div_ceil(4).max(1) }
```

- [ ] **Step 4: The syscall**

`research/src/isa.rs`, after `SYS_SHA256`:

```rust
/// M4.1's `READ_INPUT`, on the **public** segment: `a0 = idx` in, `a0 = word` out, no second
/// argument, one cpu row. The words it draws from are committed to the unsalted `H_PUB`
/// (`pv::PUB0..7`), which a verifier holding them recomputes — so a value read here is bound to
/// something the chain can check, unlike a private input under the hiding `H_IN`.
pub const SYS_READ_PUBLIC: u32 = 6;
```

`research/src/emulator.rs`: add `ReadPublic { idx: u32, word: u32 }` to `Syscall`, `PublicIndex(u32)` to `ExecError`, thread `public: &[u32]` into `execute`'s signature right after `inputs`, and add the dispatch arm beside `SYS_READ_INPUT`'s:

```rust
                        SYS_READ_PUBLIC => {
                            let word = *public.get(arg0 as usize).ok_or(ExecError::PublicIndex(arg0))?;
                            Syscall::ReadPublic { idx: arg0, word }
                        }
```

and extend the register-write predicate exactly as `ReadInput` extends it:

```rust
        let writes = dec.writes_rd == 1
            || matches!(sys, Some(Syscall::ReadInput { .. }) | Some(Syscall::ReadPublic { .. }));
```

`research/src/asm.rs`, in `mod ops`, beside `read_input`:

```rust
    pub fn read_public(idx: u32) -> Vec<Instr> { let mut v = li(REG_A7, SYS_READ_PUBLIC as i32); v.extend(li(REG_A0, idx as i32)); v.push(ecall()); v }
```

`guest-sdk/src/lib.rs`: `const SYS_READ_PUBLIC: u32 = 6;` and

```rust
/// Returns **public** input word `idx` — committed to the proof's unsalted `H_PUB`
/// (`pv::PUB0..7`), which anyone holding the words recomputes and checks
/// (`Machine::verify_public`). Use this for data the chain sees anyway (a program image, a
/// codehash, calldata): a digest the guest *declares* over these words is sound, where the
/// same declaration over `read_input` words would be bound to nothing.
/// `idx >= n_pub` can never be satisfied.
#[inline(always)]
pub fn read_public(idx: u32) -> u32 {
    let out: u32;
    unsafe {
        core::arch::asm!(
            "ecall",
            in("a7") SYS_READ_PUBLIC,
            in("a0") idx,
            lateout("a0") out,
            options(nostack),
        );
    }
    out
}
```

- [ ] **Step 5: `pv` and the `public` parameter**

`research/src/tables/cpu.rs`, in `mod pv`:

```rust
    /// The unsalted public-segment commitment `H_PUB`, pinned by the last `IS_PUBDIGEST` row
    /// (Task 2 — until then this is a declared value bound to nothing). Unlike `IN0..7` this
    /// *is* checkable by a verifier: `Machine::verify_public` recomputes
    /// `hash::public_digest(words)` from the words the chain publishes and compares.
    pub const PUB0: usize = IN0 + 8;
    pub const NUM: usize = PUB0 + 8; // 34
```

and `public_values(..)` gains an `hpub: &[u32; 8]` argument appended after `hin`, writing the eight words at `pv::PUB0`.

`research/src/machine.rs`: add `public: &[u32]` immediately after `inputs` in `build_traces`, `build_traces_salted`, `Machine::{prove, prove_salted, prove_with, prove_on}`, and pass it down. In `build_traces_salted`, before anything is sized:

```rust
    let public_digest_rows = crate::hash::public_digest_row_count(public.len());
    let cycles = exec.cycles() + program.digest_rows() + input_digest_rows + public_digest_rows;
```

(the same sum also replaces the two `None =>` tier-picking computations in `prove_salted` and `prove_on`, and `permutations` gains `public_digest_rows` for the same reason), and

```rust
    if public.len() > u16::MAX as usize { return Err(ProveError::PublicTooLong { len: public.len() }); }
```

with `ProveError::PublicTooLong { len: usize }` added beside `InputTooLong`. Compute `let hpub = crate::hash::public_digest(public);` and pass `&hpub` into `public_values`. The `public` **table** and the cpu **region** are Task 2; this task only makes the value real and available.

`research/src/guests.rs` and every other in-crate caller: add `&[]` at the new position. `rg -n 'execute\(|prove\(|prove_salted\(|prove_with\(|build_traces' research/src research/tests research/benches 2>/dev/null` finds them all.

- [ ] **Step 6: Run the tests**

Run: `cargo +1.98.1 test --test emulator --test asm --test isa`
Expected: PASS, including the three new tests. (These three files prove nothing, so no memory check is needed.)

- [ ] **Step 7: Check the rest of the crate still builds**

Run: `cargo +1.98.1 check --all-targets`
Expected: no errors. Every `execute`/`prove*`/`build_traces*` call site now passes a segment.

- [ ] **Step 8: Commit**

```bash
git add research/src/notes.rs research/src/hash.rs research/src/isa.rs research/src/emulator.rs research/src/asm.rs research/src/tables/cpu.rs research/src/machine.rs research/src/guests.rs research/tests guest-sdk/src/lib.rs
git commit -m "research: public — domain PUB, H_PUB, SYS_READ_PUBLIC = 6, the guest-SDK and asm wrappers, and the public segment threaded through execute/prove/build_traces"
```

---

### Task 2: The `public` table, its two buses, the cpu digest region, and machine integration

**Files:**
- Create: `research/src/tables/public.rs`
- Modify: `research/src/tables/mod.rs`, `research/src/tables/cpu.rs`, `research/src/machine.rs`, `research/src/guests.rs`
- Test: `research/tests/tables.rs`, `research/tests/e2e.rs`

**Interfaces:**
- Consumes: Task 1's `hash::{public_digest, public_digest_rows, public_digest_row_count}`, `pv::{PUB0, NUM}`, `emulator::Syscall::ReadPublic`, and the `public: &[u32]` parameter already threaded through `build_traces_salted`.
- Produces:

```rust
// research/src/tables/public.rs — tables::input's layout, verbatim
pub mod col { pub const IDX: usize = 0; pub const WORD: usize = 1; pub const IS_REAL: usize = 2; pub const MULT_READ: usize = 3; pub const WIDTH: usize = 4; }
pub const MIN_HEIGHT: usize = 4;
pub const MIN_LOG_HEIGHT: u8 = 2;
pub const MAX_LOG_HEIGHT: u8 = 20;
pub fn public_log_height(n: usize) -> u8;
pub struct PublicAir;
pub fn read_counts(n: usize, events: &[CycleEvent]) -> Vec<u32>;
pub fn public_trace(public: &[u32], read_counts: &[u32], height: usize) -> RowMajorMatrix<F>;

// research/src/tables/mod.rs
pub const PUBLIC_DIGEST: LookupBus<'static>;   // in mod bus
pub const PUBLIC_READ: LookupBus<'static>;

// research/src/tables/cpu.rs — appended at the end of mod col
pub const SYS_READ_PUB: usize = SYS_SHA256 + 1;
pub const IS_PUBDIGEST: usize = SYS_READ_PUB + 1;
pub const PUBDIGEST_LAST: usize = IS_PUBDIGEST + 1;
pub const IPOUT0: usize = PUBDIGEST_LAST + 1;   // 8: the last *indigest* row's permutation output
pub const PHVL0: usize = IPOUT0 + 8;            // 32
pub const PHIMAX0: usize = PHVL0 + 32;          // 4
pub const PINV0: usize = PHIMAX0 + 4;           // 4
pub const WIDTH: usize = PINV0 + 4;
pub const SELECTORS: [usize; 30];               // + SYS_READ_PUB, IS_PUBDIGEST

// research/src/machine.rs
pub enum Chip { /* … */ Public(crate::tables::public::PublicAir) }   // appended last in chips()
pub struct Traces { /* … */ pub public: RowMajorMatrix<Val>, pub public_log_height: u8 }
pub struct Proof  { /* … */ pub public_log_height: u8 }
pub enum ProveError { /* … */ PublicTooLarge { len: usize, log_height: u8 } }
pub enum VerifyError { /* … */ PublicHeight }
pub fn check_declared_heights(tier, program_log_height, input_log_height, keccak_log_height, sha256_log_height, public_log_height, mem_log_height) -> Result<(), VerifyError>;
pub fn max_constraint_degrees(tier, program_log_height, input_log_height, keccak_log_height, sha256_log_height, public_log_height, mem_log_height) -> Vec<usize>;
impl Machine {
    pub fn verifier_key(&self, tier: Tier, program_log_height: u8, input_log_height: u8, keccak_log_height: u8, sha256_log_height: u8, public_log_height: u8) -> Arc<CommonData<Config>>;
    pub fn verify(&self, hc: &[u32; 8], proof: &Proof) -> Result<(), VerifyError>;                       // unchanged signature
    pub fn verify_public(&self, hc: &[u32; 8], public_words: &[u32], proof: &Proof) -> Result<(), VerifyError>;
}

// research/src/guests.rs
pub fn public_echo() -> Program;   // reads public[0..4], sums them, writes out0; reads public[1] twice
```

- [ ] **Step 1: Write the failing tests**

Append to `research/tests/tables.rs`:

```rust
#[test]
fn public_table_rows_are_committed_words_with_their_read_counts() {
    use rand_zkvm::tables::public;
    let w = public::col::WIDTH;
    let t = public::public_trace(&[5, 6, 7], &[2, 0, 1], 8);
    assert_eq!(t.height(), 8);
    for i in 0..3 {
        assert_eq!(t.values[i * w + public::col::IDX], F::from_u32(i as u32));
        assert_eq!(t.values[i * w + public::col::IS_REAL], F::ONE);
    }
    assert_eq!(t.values[public::col::WORD], F::from_u32(5));
    assert_eq!(t.values[public::col::MULT_READ], F::from_u32(2));
    // Padding: IDX keeps counting, everything else is pinned to zero.
    assert_eq!(t.values[3 * w + public::col::IDX], F::from_u32(3));
    assert_eq!(t.values[3 * w + public::col::IS_REAL], F::ZERO);
    assert_eq!(t.values[3 * w + public::col::WORD], F::ZERO);
    assert_eq!(t.values[3 * w + public::col::MULT_READ], F::ZERO);
    // Height rule: declare n+1, floor at MIN_HEIGHT — tables::input's rule exactly.
    assert_eq!(public::public_log_height(0), public::MIN_LOG_HEIGHT);
    assert_eq!(public::public_log_height(3), 2);
    assert_eq!(public::public_log_height(4), 3);
    assert_eq!(public::public_log_height(1000), 10);
}
```

and replace `alu_max_constraint_degree_is_pinned`'s two `max_constraint_degrees` calls with six-height calls, asserting the new shapes:

```rust
    let bare = max_constraint_degrees(
        Tier(10), MIN_LOG_HEIGHT, rand_zkvm::tables::input::MIN_LOG_HEIGHT, 0, 0,
        rand_zkvm::tables::public::MIN_LOG_HEIGHT, Tier(10).min_mem_log_height(),
    );
    assert_eq!(bare.len(), 9, "nine chips when the proof declares neither hash table");
    let degrees = max_constraint_degrees(
        Tier(10), MIN_LOG_HEIGHT, rand_zkvm::tables::input::MIN_LOG_HEIGHT,
        rand_zkvm::tables::keccak::MIN_LOG_HEIGHT, rand_zkvm::tables::sha256::MIN_LOG_HEIGHT,
        rand_zkvm::tables::public::MIN_LOG_HEIGHT, Tier(10).min_mem_log_height(),
    );
    assert_eq!(degrees.len(), 11, "one degree per chip in machine::chips() order");
    // `public` is last, so dropping the two optional chips moves it from index 10 to index 8.
    assert_eq!(bare[..8], degrees[..8], "the eight mandatory non-public tables are unaffected");
    assert_eq!(bare[8], degrees[10], "the public table's degree does not depend on the hash chips");
    assert_eq!(degrees[10], 2, "public table max constraint degree: tables::input's, one bus pair, no arithmetic");
```

Append to `research/tests/e2e.rs`:

```rust
/// The public segment end to end: a guest reads it, `H_PUB` is pinned in the public values, and a
/// verifier who holds the words recomputes the digest and accepts — which is the whole point of an
/// unsalted segment, and exactly what `H_IN` cannot do.
#[test]
fn public_echo_proves_and_verify_public_checks_the_words() {
    let m = Machine::new(FriProfile::Test);
    let p = guests::public_echo();
    let public = [11u32, 22, 33, 44];
    let (proof, exec) = m.prove(&p, &[], &public, None).unwrap();
    assert_eq!(exec.outputs[0], 11 + 22 + 33 + 44 + 22); // public[1] is read twice
    m.verify(&p.digest(), &proof).unwrap();
    m.verify_public(&p.digest(), &public, &proof).unwrap();
    // pv::PUB0..7 is the native digest of exactly these words.
    let want = rand_zkvm::hash::public_digest(&public);
    for i in 0..8 {
        assert_eq!(proof.public_values[rand_zkvm::tables::cpu::pv::PUB0 + i], want[i] as u64);
    }
    // A verifier handed different words rejects, while the STARK itself still verifies.
    assert!(m.verify_public(&p.digest(), &[11, 22, 33, 45], &proof).is_err());
    assert!(m.verify_public(&p.digest(), &[11, 22, 33], &proof).is_err());
    assert_eq!(proof.public_log_height, rand_zkvm::tables::public::public_log_height(4));
}

/// Every pre-existing guest keeps proving with an empty segment, and `H_PUB` is then the fixed
/// digest of the empty vector — so `verify_public(hc, &[], proof)` accepts.
#[test]
fn an_empty_public_segment_still_has_a_digest_and_costs_four_rows() {
    let m = Machine::new(FriProfile::Test);
    let p = guests::fib(10);
    let (proof, _) = m.prove(&p, &[], &[], None).unwrap();
    m.verify_public(&p.digest(), &[], &proof).unwrap();
    assert_eq!(proof.public_log_height, rand_zkvm::tables::public::MIN_LOG_HEIGHT);
    let want = rand_zkvm::hash::public_digest(&[]);
    for i in 0..8 {
        assert_eq!(proof.public_values[rand_zkvm::tables::cpu::pv::PUB0 + i], want[i] as u64);
    }
}
```

- [ ] **Step 2: Run them and confirm they fail**

Check memory first: `ps -eo rss= | awk '$1>8000000'` → must print nothing.
Run: `cargo +1.98.1 test --test tables public_table --test e2e public_echo`
Expected: FAIL to compile — `tables::public` does not exist, `guests::public_echo` does not exist, `verify_public` does not exist.

- [ ] **Step 3: The table**

Create `research/src/tables/public.rs` as `research/src/tables/input.rs` with `input`→`public`, `INPUT_DIGEST`→`PUBLIC_DIGEST`, `INPUT_READ`→`PUBLIC_READ`, `Syscall::ReadInput`→`Syscall::ReadPublic`, `InputAir`→`PublicAir`, and its module doc comment rewritten to cite M4.1 review round 1 C1 as the *reason this table is built this way* rather than as its own history. The AIR body is byte-for-byte `InputAir::eval` with the two bus names swapped:

```rust
        b.assert_bool(v(IS_REAL));
        b.when_transition().assert_zero((one.clone() - v(IS_REAL)) * n(IS_REAL));
        b.when_first_row().assert_zero(v(IDX));
        b.when_transition().assert_zero(n(IDX) - v(IDX) - one.clone());
        // AGENTS.md invariant 1: message columns pinned on padding rows.
        b.assert_zero((one.clone() - v(IS_REAL)) * v(WORD));
        // AGENTS.md invariant 2: and the count's own witness, so a stray MULT_READ on a padding
        // row is a real rejection rather than a no-op tamper (cheating test 4).
        b.assert_zero((one.clone() - v(IS_REAL)) * v(MULT_READ));
        // The C1 split: the digest's mandatory copy and a SYS_READ_PUBLIC's copy are on separate
        // buses, so neither can borrow the other's budget.
        bus::PUBLIC_DIGEST.table_entry(b, [v(IDX), v(WORD)], v(IS_REAL));
        bus::PUBLIC_READ.table_entry(b, [v(IDX), v(WORD)], v(IS_REAL) * v(MULT_READ));
```

`read_counts` counts `Syscall::ReadPublic { idx, .. }`; `public_trace` is `input_trace` verbatim.

`research/src/tables/mod.rs`: `pub mod public;` and, in `mod bus`:

```rust
    /// cpu (real `IS_PUBDIGEST` rows) → public: (idx, word), count 1 per absorbed word. The
    /// public table provides with count `IS_REAL`. Split from `PUBLIC_READ` for the reason
    /// `INPUT_DIGEST` is split from `INPUT_READ` (M4.1 review round 1, C1): LogUp balances per
    /// (idx, word) key, not per consumer class, so one bus would let a prover shrink the
    /// digest's absorbed set while a genuine read of the dropped index still succeeded.
    pub const PUBLIC_DIGEST: LookupBus<'static> = LookupBus::new("PUBLIC_DIGEST");
    /// cpu (`SYS_READ_PUB` rows) → public: (idx, word), count `MULT_READ` per real row.
    pub const PUBLIC_READ: LookupBus<'static> = LookupBus::new("PUBLIC_READ");
```

- [ ] **Step 4: The cpu region — `IPOUT0..7` first**

In `research/src/tables/cpu.rs`, **before** touching anything else, add `IPOUT0..7` and retarget the last indigest row's two consumers of `n(HS0 + j)`:

```rust
    /// The last *indigest* row's own permutation output. Exactly what `DPOUT0..7` is for the
    /// last program-digest row, one region later and for the identical reason: the row after
    /// the last indigest row is now the first `IS_PUBDIGEST` row, whose `n(HS0..7)` is
    /// repurposed to seed `H_PUB`'s capacity header — so H_IN's own output can no longer be
    /// read back through `n(HS0 + j)`. Two unrelated values cannot occupy one cell; asserting
    /// both is unsatisfiable even for an honest witness (M4.1 found this the hard way).
    pub const IPOUT0: usize = PUBDIGEST_LAST + 1;
```

and change both places that read `n(HS0 + j)` under `indigest_last`:

```rust
                t.assert_zero(indigest_last.clone() * (lo.clone() + hi.clone() * two32.clone() - v(IPOUT0 + j)));
```

plus the `POSEIDON2` bus lookup's `state_out` argument on the last indigest row, which targets `v(IPOUT0 + i)` where it previously targeted `n(HS0 + i)` — the same conditional shape `DIGEST_LAST` already uses for `DPOUT0`. `fill_input_digest_rows` writes the block's `state_out` into `IPOUT0..7` on the last row.

Then add the region proper, mirroring the `IS_INDIGEST` block:

* `IS_PUBDIGEST` and `PUBDIGEST_LAST` as booleans; `IS_DIGEST`, `IS_HASH`, `IS_INDIGEST`, `IS_PUBDIGEST` pairwise mutually exclusive; both added to `SELECTORS` where they belong (`IS_PUBDIGEST` and `SYS_READ_PUB` go in; `PUBDIGEST_LAST` does not, mirroring `INDIGEST_LAST`).
* The header seed on the transition out of `INDIGEST_LAST`, mirroring `digest_last`'s seed of the H_IN header — and note the one difference: **no salt row**, so `HASH_IDX` starts at 0 on the first pubdigest row and every real row drains `HASH_LEFT` by its own `active_sum` (there is no `IS_SALT` analogue and no `indigest_drain`-style exemption):

```rust
            for i in [0usize, 1, 2, 3, 7] { t.assert_zero(indigest_last.clone() * n(HS0 + i)); }
            t.assert_zero(indigest_last.clone() * (n(HS0 + 4) - AB::Expr::from_u32(crate::notes::domain::PUB)));
            t.assert_zero(indigest_last.clone() * (n(HS0 + 5) - n(HASH_N)));
            t.assert_zero(indigest_last.clone() * n(HS0 + 6));
            t.assert_zero(indigest_last.clone() * n(HASH_IDX));
            t.assert_zero(indigest_last.clone() * (n(HASH_LEFT) - n(HASH_N)));
            let not_final_pubdigest = is_pubdigest.clone() * n(IS_PUBDIGEST);
            t.assert_zero(not_final_pubdigest.clone() * (n(HASH_N) - v(HASH_N)));
            t.assert_zero(is_pubdigest.clone() * (v(HASH_LEFT) - active_sum.clone() - n(HASH_LEFT)));
            t.assert_zero(pubdigest_last.clone() * (v(HASH_LEFT) - active_sum.clone()));
            t.assert_zero(not_final_pubdigest.clone() * (n(HASH_IDX) - v(HASH_IDX) - one.clone()));
            t.assert_zero(not_final_pubdigest * (one.clone() - v(ACT0 + 3)));
```

* Each active lane consumes `PUBLIC_DIGEST`, mirroring the indigest rows' `INPUT_DIGEST` consume — and with **no salt row there is no `IS_SALT` gate**, so every real pubdigest row's lanes are checked:

```rust
        for k in 0..4u32 {
            let pub_idx = v(HASH_IDX) * AB::Expr::from_u32(4) + AB::Expr::from_u32(k);
            bus::PUBLIC_DIGEST.lookup_key(b, [pub_idx, v(HV0 + k as usize)], Count::bounded(is_pubdigest.clone() * v(ACT0 + k as usize), 1));
        }
```

* `PUBDIGEST_LAST` pins `pv::PUB0..7` through `PHVL0..31`/`PHIMAX0..3`/`PINV0..3` — `INDIGEST_LAST`'s `IHVL`/`IHIMAX`/`IINV` block verbatim, reading `n(HS0 + j)` (the row after the last pubdigest row is an ordinary instruction row, which has no header to seed, so this one *can* use `n(HS0..)`), with the `RANGE8` byte lookups and the canonical-encoding `d * PINV = 1 - PHIMAX` / `PHIMAX * lo = 0` pair.
* The `SYS_READ_PUB` row kind: `sys_sum` gains `v(SYS_READ_PUB)`; `defines_c` gains it; the register-writeback `count3` gains it; `off_cpu` zeroes it; `b.assert_zero(v(SYS_READ_PUB) * (v(A) - AB::Expr::from_u32(SYS_READ_PUBLIC)));` and

```rust
        // The only constraint that pins a SYS_READ_PUB row's returned value (`C`, already written
        // back to `a0` by the shared register-write path). Draws from PUBLIC_READ, never
        // PUBLIC_DIGEST — the C1 split again: a read can never affect the digest's own count.
        bus::PUBLIC_READ.lookup_key(b, [v(B), v(C)], Count::bounded(v(SYS_READ_PUB), 1));
```

* `fill_public_digest_rows(v, offset, public, range)` mirrors `fill_input_digest_rows` without the salt row; `cpu_trace` gains `public: &[u32]` and calls it after `fill_input_digest_rows`; the first instruction row's offset becomes `program.digest_rows() + input_digest_row_count(n_in) + public_digest_row_count(n_pub)`.

- [ ] **Step 5: Machine integration**

`research/src/machine.rs`:
* `Chip::Public(PublicAir)` in the enum and in all four `match`es; pushed **last** in `chips(tier, keccak_log_height, sha256_log_height)` (after the two conditional pushes), with a doc-comment paragraph saying why "last" keeps `i == 1`/`i == 2` fixed and that its index is consequently 8, 9 or 10.
* `Traces { public, public_log_height }`; `as_slice` pushes `&self.public` last.
* `Proof { public_log_height: u8 }` with a doc comment on what it leaks (`n_pub` to within a factor of two; `MIN_LOG_HEIGHT` means "no public segment").
* `log_ext_degrees(.., public_log_height, mem_log_height)` pushes `public_log_height as usize + zk` last.
* `verifier_key` takes `public_log_height` as the sixth component of both the signature and the cache key.
* `check_declared_heights` gains `public_log_height` after `sha256_log_height` and, after the sha256 block:

```rust
    // The public table is mandatory — unlike the two hash chips there is no "0 means absent"
    // value — so this is a plain range check, `tables::input`'s exactly.
    if !(crate::tables::public::MIN_LOG_HEIGHT..=crate::tables::public::MAX_LOG_HEIGHT).contains(&public_log_height) {
        return Err(VerifyError::PublicHeight);
    }
```

* `build_traces_salted`: `let public_log_height = crate::tables::public::public_log_height(public.len());` with the `PublicTooLarge` guard, `let read_counts = tables::public::read_counts(public.len(), &exec.events);`, `let public_t = tables::public::public_trace(public, &read_counts, 1usize << public_log_height);`, and the pubdigest blocks appended to `all_hash_events` **after** the indigest ones and before the absorb ones:

```rust
    let pubdigest_blocks = crate::hash::public_digest_rows(public);
    let pubdigest_events: Vec<Poseidon2Event> = pubdigest_blocks.iter().map(|blk| {
        let mut input = blk.state_in;
        for k in 0..4 { if blk.active[k] { input[k] = Val::from_u32(blk.words[k]); } }
        Poseidon2Event { input, output: blk.state_out }
    }).collect();
```

  `clk_offset` becomes `(program.digest_rows() + input_digest_rows + public_digest_rows) as u32`.
* `verify` passes `proof.public_log_height` to `check_declared_heights`, `log_ext_degrees`, `verifier_key` and keeps its own signature; `prove_traces`/`prove_on` carry the field into `Proof`.
* And the new entry point:

```rust
    /// `verify`, plus the check the public segment exists for: `hash::public_digest(public_words)`
    /// recomputed natively and compared against `pv::PUB0..7`. This is what a chain calls — it
    /// publishes the words with the transaction and checks that the proof committed to exactly
    /// them. `verify` alone leaves `pv::PUB0..7` unchecked against anything outside the proof
    /// (it is still pinned *in-circuit* to whatever the `public` table supplied, so the guest's
    /// reads and the digest agree; what `verify` cannot know is which words those were).
    pub fn verify_public(&self, hc: &[u32; 8], public_words: &[u32], proof: &Proof) -> Result<(), VerifyError> {
        self.verify(hc, proof)?;
        let want = crate::hash::public_digest(public_words);
        for i in 0..8 {
            if proof.public_values[crate::tables::cpu::pv::PUB0 + i] != want[i] as u64 {
                return Err(VerifyError::PublicValues);
            }
        }
        Ok(())
    }
```

`research/src/guests.rs`:

```rust
/// Reads the four public words, sums them, and reads `public[1]` a second time — so one proof
/// exercises a multi-word digest region, a `MULT_READ` of 2, and the `PUBLIC_READ` bus.
pub fn public_echo() -> Program {
    let mut a = Assembler::new(0);
    a.extend(ops::read_public(0));
    a.push(ops::mv(5, REG_A0));
    for i in [1u32, 2, 3] {
        a.extend(ops::read_public(i));
        a.push(ops::add(5, 5, REG_A0));
    }
    a.extend(ops::read_public(1));
    a.push(ops::add(5, 5, REG_A0));
    a.extend(ops::write_output(0, 5));
    a.extend(ops::halt());
    a.assemble()
}
```

- [ ] **Step 6: Run the tests**

Check memory first: `ps -eo rss= | awk '$1>8000000'` → must print nothing.
Run: `cargo +1.98.1 test --test tables --test e2e public`
Expected: PASS. If `honest_traces_pass`-style constraint panics appear instead, the cause is almost certainly the `IPOUT0` retarget of Step 4 — re-read that step before debugging anything else.

- [ ] **Step 7: The rest of the suite still passes**

Check memory first: `ps -eo rss= | awk '$1>8000000'` → must print nothing.
Run: `cargo +1.98.1 test --release 2>&1 | grep -E 'test result|FAILED'`
Expected: every binary `ok`; the ignored count is unchanged at 6.

- [ ] **Step 8: Commit**

```bash
git add research/src/tables/public.rs research/src/tables/mod.rs research/src/tables/cpu.rs research/src/machine.rs research/src/guests.rs research/tests/tables.rs research/tests/e2e.rs
git commit -m "research: public — the public witness table, the PUBLIC_DIGEST/PUBLIC_READ bus pair, the IS_PUBDIGEST cpu region pinning pv::PUB0..7, and Machine::verify_public"
```

---

### Task 3: Cheating tests

**Files:**
- Modify: `research/tests/cheating.rs`

**Interfaces:**
- Consumes: everything Tasks 1 and 2 produce. These tests mirror M4.1's input-table attacks one for one — `two_reads_of_the_same_index_returning_different_words_is_rejected`, `a_read_disagreeing_with_the_committed_input_word_is_rejected`, `tampering_h_in_in_public_values_is_rejected`, `an_extra_real_input_row_at_idx_equal_to_n_in_is_rejected`, `a_mult_read_bumped_on_an_input_padding_row_is_rejected`, `a_hole_in_the_input_tables_real_prefix_is_rejected`, `a_skipped_input_table_index_is_rejected` — and add the two the `public` segment has that `input` does not (a forged declared height, and a `SYS_READ_PUBLIC` row hidden behind padding).
- Produces: no API.

- [ ] **Step 1: Write the failing tests**

Append to `research/tests/cheating.rs`:

```rust
// ---- the public segment (constraint set 6) ------------------------------------------------------

fn setup_with_public(public: &[u32]) -> (Machine, rand_zkvm::isa::Program, Traces) {
    let m = Machine::new(FriProfile::Test);
    let p = guests::public_echo(); // reads public[0..4], and public[1] twice
    let e = execute(&p, &[], public, 10_000).unwrap();
    let t = build_traces_salted(&p, &[], public, TEST_SALT, &e, Tier(10)).unwrap();
    (m, p, t)
}

/// (1) A real `public` row outside `{0..n_pub-1}`: an unclaimed `PUBLIC_DIGEST` supply the digest
/// never demands, rejected whether or not anything claims to read it.
#[test]
fn a_real_public_row_past_n_pub_is_rejected() {
    use rand_zkvm::tables::public::col;
    let (m, p, mut t) = setup_with_public(&[11, 22, 33, 44]);
    let w = col::WIDTH;
    assert!(t.public.height() > 4, "the +1 padding-row rule leaves spare rows past the four real ones");
    t.public.values[4 * w + col::WORD] = F::from_u32(999);
    t.public.values[4 * w + col::IS_REAL] = F::ONE;
    assert!(rejects(|| { let pr = m.prove_traces(&p, &t, Tier(10)); m.verify(&p.digest(), &pr) }));
}

/// (2) A word the digest did not absorb but a read returned: tamper the committed row's WORD, so
/// the honest `SYS_READ_PUB` row's `C` no longer matches what `H_PUB` absorbed.
#[test]
fn a_public_read_disagreeing_with_the_committed_word_is_rejected() {
    use rand_zkvm::tables::public::col;
    let (m, p, mut t) = setup_with_public(&[11, 22, 33, 44]);
    t.public.values[col::WORD] += F::ONE;
    assert!(rejects(|| { let pr = m.prove_traces(&p, &t, Tier(10)); m.verify(&p.digest(), &pr) }));
}

/// (3) A read of a dropped index: clear a real row's `IS_REAL` while the guest still reads it.
/// Two independent rules catch it — the prefix rule, and `PUBLIC_DIGEST`'s unclaimed demand.
#[test]
fn a_read_of_a_dropped_public_index_is_rejected() {
    use rand_zkvm::tables::public::col;
    let (m, p, mut t) = setup_with_public(&[11, 22, 33, 44]);
    let w = col::WIDTH;
    t.public.values[3 * w + col::IS_REAL] = F::ZERO;
    t.public.values[3 * w + col::WORD] = F::ZERO;
    t.public.values[3 * w + col::MULT_READ] = F::ZERO;
    assert!(rejects(|| { let pr = m.prove_traces(&p, &t, Tier(10)); m.verify(&p.digest(), &pr) }));
}

/// (4) `MULT_READ` forged on a padding row — the AGENTS.md invariant-2 regression. The count's
/// `IS_REAL` factor already zeroes the supply, so what rejects this is the explicit padding pin,
/// which is exactly why that pin exists.
#[test]
fn a_mult_read_bumped_on_a_public_padding_row_is_rejected() {
    use rand_zkvm::tables::public::col;
    let (m, p, mut t) = setup_with_public(&[11, 22, 33, 44]);
    let w = col::WIDTH;
    assert_eq!(t.public.values[5 * w + col::IS_REAL], F::ZERO, "row 5 is padding");
    t.public.values[5 * w + col::MULT_READ] = F::from_u32(3);
    assert!(rejects(|| { let pr = m.prove_traces(&p, &t, Tier(10)); m.verify(&p.digest(), &pr) }));
}

/// (5) A forged `H_PUB` public value.
#[test]
fn tampering_h_pub_in_public_values_is_rejected() {
    let (m, p, mut t) = setup_with_public(&[11, 22, 33, 44]);
    t.public_values[cpu::pv::PUB0] += F::ONE;
    assert!(rejects(|| { let pr = m.prove_traces(&p, &t, Tier(10)); m.verify(&p.digest(), &pr) }));
}

/// (6) A mismatched `public_log_height`: the declared height and the batch's degree bits disagree,
/// which `verify`'s degree-bits equality catches before any verifier key is built.
#[test]
fn a_mismatched_public_height_is_rejected_before_any_verifier_key_is_built() {
    let (m, p, t) = setup_with_public(&[11, 22, 33, 44]);
    let mut pr = m.prove_traces(&p, &t, Tier(10));
    pr.public_log_height += 1;
    let fresh = Machine::new(FriProfile::Test);
    assert!(fresh.verify(&p.digest(), &pr).is_err());
    assert_eq!(fresh.cached_keys(), 0, "rejected before the preprocessed commitment is recomputed");
}

/// (6b) And a declared height outside `[MIN_LOG_HEIGHT, MAX_LOG_HEIGHT]` is an error, not a panic —
/// the untrusted-shift guard `check_declared_heights` exists for.
#[test]
fn out_of_range_declared_public_heights_are_errors_not_panics() {
    use rand_zkvm::machine::{check_declared_heights, VerifyError};
    use rand_zkvm::tables::public;
    let t = Tier(10);
    for h in [0u8, 1, public::MAX_LOG_HEIGHT + 1, 200] {
        assert!(matches!(
            check_declared_heights(t, rand_zkvm::tables::program::MIN_LOG_HEIGHT, rand_zkvm::tables::input::MIN_LOG_HEIGHT, 0, 0, h, t.min_mem_log_height()),
            Err(VerifyError::PublicHeight)
        ), "public_log_height {h}");
    }
}

/// (7) A `SYS_READ_PUBLIC` row in a proof whose public table is padded to hide it: zero out every
/// real row of the table (so it declares an empty segment) while the cpu table's read row stands.
/// `PUBLIC_READ` then has no provider for that `(idx, word)` at all.
#[test]
fn a_public_read_whose_table_is_padded_away_is_rejected() {
    use rand_zkvm::tables::public::col;
    let (m, p, mut t) = setup_with_public(&[11, 22, 33, 44]);
    let w = col::WIDTH;
    for r in 0..4 {
        t.public.values[r * w + col::IS_REAL] = F::ZERO;
        t.public.values[r * w + col::WORD] = F::ZERO;
        t.public.values[r * w + col::MULT_READ] = F::ZERO;
    }
    assert!(rejects(|| { let pr = m.prove_traces(&p, &t, Tier(10)); m.verify(&p.digest(), &pr) }));
}

/// (8) A hole in the real-row prefix — the monotone-prefix rule, and independently the digest's
/// unclaimed demand at the hole's index.
#[test]
fn a_hole_in_the_public_tables_real_prefix_is_rejected() {
    use rand_zkvm::tables::public::col;
    let (m, p, mut t) = setup_with_public(&[11, 22, 33, 44]);
    let w = col::WIDTH;
    assert_eq!(t.public.values[2 * w + col::IS_REAL], F::ONE, "row 2 is real, so clearing row 1 leaves a hole");
    t.public.values[w + col::IS_REAL] = F::ZERO;
    assert!(rejects(|| { let pr = m.prove_traces(&p, &t, Tier(10)); m.verify(&p.digest(), &pr) }));
}

/// (9) A skipped index in the `IDX` chain — it would otherwise mis-key every `PUBLIC_DIGEST`
/// and `PUBLIC_READ` message from that row on.
#[test]
fn a_skipped_public_table_index_is_rejected() {
    use rand_zkvm::tables::public::col;
    let (m, p, mut t) = setup_with_public(&[11, 22, 33, 44]);
    let w = col::WIDTH;
    t.public.values[w + col::IDX] += F::ONE;
    assert!(rejects(|| { let pr = m.prove_traces(&p, &t, Tier(10)); m.verify(&p.digest(), &pr) }));
}

/// (10) Two reads of the same public index returning different words — `public_echo` reads
/// `public[1]` twice, so the second read's row is there to tamper.
#[test]
fn two_public_reads_of_the_same_index_returning_different_words_is_rejected() {
    let (m, p, mut t) = setup_with_public(&[11, 22, 33, 44]);
    let w = cpu::col::WIDTH;
    let read_rows: Vec<usize> = (0..t.cpu.height()).filter(|&i| t.cpu.values[i * w + cpu::col::SYS_READ_PUB] == F::ONE).collect();
    assert_eq!(read_rows.len(), 5, "public_echo makes five READ_PUBLIC calls");
    t.cpu.values[read_rows[4] * w + cpu::col::C] += F::ONE;
    assert!(rejects(|| { let pr = m.prove_traces(&p, &t, Tier(10)); m.verify(&p.digest(), &pr) }));
}
```

- [ ] **Step 2: Run them**

Check memory first: `ps -eo rss= | awk '$1>8000000'` → must print nothing.
Run: `cargo +1.98.1 test --release --test cheating public`
Expected: every one PASS. `rejects()` counts only a constraint panic, a lookup-balance panic or a verify error — a trace-builder `assert!` means the test tripped on something else and must be rewritten, not accepted (`research/AGENTS.md`).

- [ ] **Step 3: Commit**

```bash
git add research/tests/cheating.rs
git commit -m "research: public — cheating tests for the public segment (rows past n_pub, forged words, dropped indices, padding-row MULT_READ, forged H_PUB, mismatched height, a read hidden behind padding, prefix holes, index skips, disagreeing repeat reads)"
```

---

### Task 4: The sBPF guest — ELF from the public segment, canonical `input_hash`

**Files:**
- Modify: `guests-compiled/sbpf-core/src/abi.rs`, `guests-compiled/sbpf/src/main.rs`, `research/src/sbpf.rs`, `research/tests/sbpf_abi.rs`
- Rebuild: `guests-compiled/bin/sbpf.bin` and `.sha256`

**Interfaces:**
- Consumes: `guest_sdk::read_public` (Task 1), `emulator::execute(program, inputs, public, max_cycles)` (Task 1).
- Produces:

```rust
// guests-compiled/sbpf-core/src/abi.rs
pub fn canonical_input_hash<H: Host>(h: &mut H, input: &[u8], program_id: &[u8; 32]) -> [u8; 32];
pub fn public_output<H: Host>(h: &mut H, status: u32, input_hash: &[u8; 32], output_hash: &[u8; 32]) -> [u32; 8];
pub fn decode_input<FP: FnMut(u32) -> u32, FS: FnMut(u32) -> u32>(dst: &mut CallInput, elf_c: &mut InputCursor<FP>, in_c: &mut InputCursor<FS>) -> Result<(), ParseError>;
pub fn run_call<H: Host, FP: FnMut(u32) -> u32, FS: FnMut(u32) -> u32>(h: &mut H, ws: &mut Workspace, read_public: FP, n_public: u32, read_private: FS, n_private: u32) -> [u32; 8];
pub fn run_call_with<H: Host, FP: FnMut(u32) -> u32, FS: FnMut(u32) -> u32>(h: &mut H, ws: &mut Workspace, read_public: FP, n_public: u32, read_private: FS, n_private: u32) -> ([u32; 8], Result<u64, Halt>);

// research/src/sbpf.rs
impl SbpfCall {
    pub fn public_words(&self) -> Vec<u32>;   // [n_elf, elf bytes…]
    pub fn input_words(&self) -> Vec<u32>;    // [n_input, input bytes…]  (ELF removed)
}
```

- [ ] **Step 1: Write the failing tests**

Append to `research/tests/sbpf_abi.rs`:

```rust
/// The canonical input encoding, field by field, against a hand-built expectation — and the
/// measurement that justifies it: the aligned region's 98 % realloc padding is gone.
#[test]
fn canonical_input_hash_is_the_unpadded_encoding_and_is_two_orders_smaller() {
    use rand_zkvm::sbpf::{canonical_preimage, spl_transfer, deserialize_accounts, SPL_TOKEN_ID};
    let call = spl_transfer(250);
    let pre = canonical_preimage(&call.input);
    // program id, u64 n_accounts, then per account key‖owner‖lamports‖data_len‖data‖3 flag bytes,
    // then u64 instruction_data_len ‖ instruction data.
    assert_eq!(&pre[..32], &SPL_TOKEN_ID[..]);
    let accounts = deserialize_accounts(&call.input);
    assert_eq!(u64::from_le_bytes(pre[32..40].try_into().unwrap()), accounts.len() as u64);
    let want: usize = 32 + 8 + accounts.iter().map(|a| 32 + 32 + 8 + 8 + a.data.len() + 3).sum::<usize>() + 8 + call_instruction_data_len(&call.input);
    assert_eq!(pre.len(), want);
    // The number this change exists for: 41 825 aligned bytes -> under a kilobyte.
    assert!(pre.len() < 1_024, "canonical preimage is {} bytes", pre.len());
    assert!(pre.len().div_ceil(64) + 1 <= 16, "at most ~14 compressions, was 654");
}

/// Two segments: the ELF is read with `read_public`, the instruction with `read_input`, and the
/// guest's eight output words are the digest over the *two* hashes, not three.
#[test]
fn the_sbpf_abi_reads_the_elf_from_the_public_segment() {
    use rand_zkvm::sbpf::spl_transfer;
    let call = spl_transfer(250);
    let public = call.public_words();
    let private = call.input_words();
    assert_eq!(public[0] as usize, call.elf.len());
    assert_eq!(private[0] as usize, call.input.len());
    assert!(private.len() < 12_000, "the ELF is no longer on the private tape: {} words", private.len());
    let (out, r0, _post) = call.expected();
    assert_eq!(r0, Ok(0));
    assert_eq!(out[0], 1);
    // out1..7 is hash(SBPF_OUT, [input_hash ‖ output_hash]) — 16 words, not 24.
    let mut h = rand_zkvm::sbpf::HostRef;
    let want = sbpf_core::abi::public_output(&mut h, 1, &rand_zkvm::sbpf::canonical_input_hash_of(&call.input), &rand_zkvm::sbpf::output_hash_of(&call.input_post_state()));
    assert_eq!(out, want);
}
```

(`canonical_preimage`, `canonical_input_hash_of`, `output_hash_of`, `call_instruction_data_len`, `input_post_state` and `SPL_TOKEN_ID` are thin host-side helpers in `research/src/sbpf.rs`; write them alongside the test rather than inlining byte offsets in the test.)

- [ ] **Step 2: Run them and confirm they fail**

Run: `cargo +1.98.1 test --test sbpf_abi canonical --test sbpf_abi public_segment`
Expected: FAIL to compile — `canonical_preimage`, `public_words` and the five-argument `public_output` do not exist.

- [ ] **Step 3: `sbpf-core`**

* `CallInput` keeps its two buffers; `decode_input` takes **two** cursors and fills `elf` from the public one and `input` from the private one, keeping the same "refuse, rather than trust, every length" discipline (both `ElfTooLong`/`InputTooLong`, and `Truncated` if either cursor ended early).
* `canonical_input_hash(h, input, program_id)` walks the aligned region with `output_hash`'s own `seen`/duplicate-ordinal logic (a duplicate re-encodes, in full, the account it duplicates, at the position it occupies) and feeds the `Sha256` sponge the fields of spec §9.4's table in order. Reuse `output_hash`'s walk rather than writing a second one — factor the walk into an iterator-shaped helper both call, so the two can never drift on duplicates.
* `public_output(h, status, input_hash, output_hash)` drops the `program_hash` argument; `msg` is `[u32; 16]`, `msg[0..8] = hash_words(input_hash)`, `msg[8..16] = hash_words(output_hash)`; the `SBPF_OUT` domain and the `out[0] = status`, `out[1..8] = d[..7]` shape are unchanged.
* `run_call_with` drops `let program_hash = sha256(h, &elf[..elf_len]);` entirely and uses `canonical_input_hash` where it used `sha256(h, &input[..input_len])`. The malformed-vector early return becomes `public_output(h, 2, &z, &z)`.
* Update the module doc comment's digest description (`hash(SBPF_OUT, [input_hash(8) ‖ output_hash(8)])`), and say in one sentence why `program_hash` is gone: the ELF is in the public segment, so `H_PUB` binds it and the chain checks it.

`guests-compiled/sbpf/src/main.rs`:

```rust
    let out = run_call(
        &mut Syscalls,
        w,
        guest_sdk::read_public,
        u32::MAX,
        guest_sdk::read_input,
        u32::MAX,
    );
```

with the existing comment updated: a read past either segment's committed length is unsatisfiable in-circuit, so the machine is the bound on both and `u32::MAX` is the honest `len` for each.

`research/src/notes.rs`: `domain::SBPF_OUT`'s doc comment now describes a 16-word preimage.

`research/src/sbpf.rs`: `SbpfCall::public_words()` (`[n_elf, elf bytes…]`), `input_words()` (`[n_input, input bytes…]`), and `expected()` running `run_call_with` over both cursors; plus the four host helpers the tests use.

- [ ] **Step 4: Run the host tests**

Run: `cargo +1.98.1 test --test sbpf_abi --test sbpf_interp --test sbpf_elf --test sbpf_isa`
Expected: PASS. These four files prove nothing, so they are cheap and need no memory check. Fix `sbpf-core` here, natively, before anything is rebuilt — an interpreter cannot be debugged through proofs (`research/AGENTS.md`).

- [ ] **Step 5: Rebuild the guest**

Run: `make -C guests-compiled/sbpf install`
(`install`, **not** `all`: `all` leaves the image in the guest crate's own `bin/`, and `src/guests.rs` includes `guests-compiled/bin/sbpf.bin`, so without it every test measures the *previous* binary.)
Then: `shasum -a 256 guests-compiled/bin/sbpf.bin > guests-compiled/bin/sbpf.bin.sha256`

- [ ] **Step 6: Check the guest against the native run**

Check memory first: `ps -eo rss= | awk '$1>8000000'` → must print nothing.
Run: `cargo +1.98.1 test --release --test e2e compiled_sbpf_spl_token_transfer_executes -- --nocapture`
Expected: PASS, with the executor's eight output words equal to the native run's. Update that test's two cycle tripwires to the newly measured number (the upper bound just above it, the lower bound still `Tier(20).max_cycles()` so it fires the day the guest fits) and its `compressions` assertion — it is now `canonical input_hash blocks + 8 + 8`, not `1698 + 654 + 16`.

- [ ] **Step 7: Commit**

```bash
git add guests-compiled/sbpf-core guests-compiled/sbpf guests-compiled/bin/sbpf.bin guests-compiled/bin/sbpf.bin.sha256 research/src/sbpf.rs research/src/notes.rs research/tests/sbpf_abi.rs research/tests/e2e.rs
git commit -m "research: sbpf — the ELF moves to the public segment, program_hash is dropped, input_hash over a canonical unpadded instruction encoding; guest rebuilt"
```

---

### Task 5: The exit-test measurement and the docs

**Files:**
- Modify: `research/tests/e2e.rs`, `research/docs/01-isa.md`, `research/docs/02-tables-and-buses.md`, `research/docs/03-privacy.md`, `research/docs/04-guests.md`, `research/docs/05-roadmap.md`, `research/README.md`, `research/AGENTS.md`

**Interfaces:**
- Consumes: everything above. Produces no API.

- [ ] **Step 1: Measure the exit test**

Check memory first: `ps -eo rss= | awk '$1>8000000'` → must print nothing. This is the largest run in the plan; nothing else may be proving.

Update `compiled_sbpf_spl_token_transfer_proves_and_verifies` to the new API (`m.prove_salted(&p, &private, &public, [13, 14, 15, 16], None)`, `m.verify_public(&p.digest(), &public, &proof)`) and to print the full line:

```rust
    eprintln!(
        "sbpf spl transfer: {} program words, {} private input words, {} public words, {} cycles, \
         {} sha256 compressions, tier {}, sha256_log_height {}, public_log_height {}, \
         mem_log_height {}, proof {} bytes",
        p.len(), private.len(), public.len(), exec.cycles(),
        exec.events.iter().filter(|e| e.sha256_row.is_some()).count(),
        proof.tier.0, proof.sha256_log_height, proof.public_log_height, proof.mem_log_height,
        proof.size(),
    );
```

Run: `cargo +1.98.1 test --release --test e2e compiled_sbpf_spl_token_transfer_proves_and_verifies -- --ignored --nocapture`

- [ ] **Step 2: Decide the test's fate on the measurement, and record it**

Spec §9.5 projects ~699 K cycles, i.e. `Tier(20)`. Apply the rule, do not negotiate with it:

* **Un-ignore** the test only if the measured tier is **≤ 18** *and* the proof completed here. Then drop the `#[ignore]`, keep the `assert!(proof.tier.0 <= 18)`, and say so in `docs/05-roadmap.md` — M4's exit criterion is met on the SPL side.
* **Otherwise it stays `#[ignore]`d**, with the *new* measurement in the message and the ≥ 64 GB path written down exactly as M4.3's tier-18 EVM proof has it (`docs/04-guests.md`: the command, the resident-set figure at SIGKILL, and the machine size that would produce the artefact). If the run was killed rather than completing, record the resident-set high-water mark at the kill and the number of attempts, as M4.3's entry does.

Either way, `compiled_sbpf_spl_token_transfer_executes_and_publishes_the_bound_digest` — the executor-level half, which tripwires in both directions on the cycle count — is what pins the behaviour, and its bounds must match the new measurement.

- [ ] **Step 3: Docs**

* **`docs/01-isa.md`** — a row `| 6 | READ_PUBLIC idx | CS6 | returns public segment word idx in a0 — committed to the unsalted H_PUB (pv::PUB0..7), which a verifier holding the words recomputes (Machine::verify_public); two reads of the same idx agree and idx >= n_pub cannot be satisfied at all |`, and a sentence in the syscall preamble distinguishing the two input spaces.
* **`docs/02-tables-and-buses.md`** — a `## public — main, col::WIDTH = 4 (CS6)` section directly after the `input` one, carrying the two-bus C1 argument in the public segment's own terms, the padding pins, and the height rule; the bus count 14 → 16 in the opening paragraph and the ASCII diagram; the `IS_PUBDIGEST` region and `IPOUT0..7` in the cpu section (say plainly that `IPOUT0` is `DPOUT0`'s twin and why); the constraint-degree list gaining `public 2` and the note that the pin test now asserts nine- and eleven-chip shapes.
* **`docs/03-privacy.md`** — the sBPF leak row rewritten (the ELF is now **published**, the digest is over two hashes not three, and `sha256_log_height` no longer bounds the program size); the general statement "the public segment is published by construction — that is its purpose; a guest that wants its program hidden keeps it in the private input as before"; a new `public_log_height` structural row; and an explicit note that the EVM guest (M4.3) is **not** changed by this work and keeps its bytecode private, though it may adopt the segment later.
* **`docs/04-guests.md`** — "The `sbpf` guest" updated end to end: option B taken, the new measured table (program words, private input words, public words, cycles, compressions, tier, `sha256_log_height`, `public_log_height`, `mem_log_height`, proof size), the canonical `input_hash` encoding, and — importantly — the correction that B lands at **tier 20, not 18**, with §9.5's arithmetic and the tape cost named as the remaining lever (a bulk public-read syscall).
* **`docs/05-roadmap.md`** — the M4 row: constraint set 6 landed, what it changes, and the honest status of the exit criterion after this work; test counts re-measured.
* **`README.md`** and **`AGENTS.md`** — nine mandatory tables (ten/eleven with the optional hash chips), sixteen buses, the new suite timings and the new total test count, and `AGENTS.md`'s "Commands" paragraph updated: the sBPF ignore-message text it quotes has changed, and its "do not fix the sBPF one by declaring `program_hash`" warning now needs its resolution ("the public segment is how that was made sound — see spec §9").

Every number in these docs is re-measured, not carried over. Run `cargo +1.98.1 test --release 2>&1 | grep -E 'test result'` once (memory-checked) and take the counts and timings from that run.

- [ ] **Step 4: Full suite**

Check memory first: `ps -eo rss= | awk '$1>8000000'` → must print nothing.
Run: `cargo +1.98.1 test --release 2>&1 | grep -E 'test result|FAILED'`
Expected: every binary `ok`. The pre-existing `--features reference-backend` failure (`backend_proof_has_the_same_shape_as_a_cpu_proof`, unpassable since M4.1 salted `H_IN`) is out of scope and must not be "fixed" here.

- [ ] **Step 5: Commit**

```bash
git add research/tests/e2e.rs
git commit -m "research: sbpf — the exit test re-measured on the public segment"
git add research/docs research/README.md research/AGENTS.md
git commit -m "research: docs — the public input segment (constraint set 6): the public table and its two buses, SYS_READ_PUBLIC, H_PUB and verify_public, the sBPF guest's new binding, and the measured numbers"
```

## Self-review

**Spec coverage (§9).** §9.1 the `public` table, the two buses, the `IS_PUBDIGEST` region, `domain::PUB`, `pv::PUB0..7`/`NUM = 34`, and the `IPOUT0..7` fix → Tasks 1 (domain, digest, pv) and 2 (table, buses, region, `IPOUT0`). §9.2 `SYS_READ_PUBLIC = 6`, the out-of-range rule, the SDK and asm wrappers, the prover API, `Proof`/`Traces`/`verifier_key`/`check_declared_heights`/`log_ext_degrees`, `Chip::Public` last → Tasks 1 and 2. §9.3 `verify` unchanged, `verify_public` added, `n_pub = 0` and `public = &[]` → Task 2 (both e2e tests). §9.4 the sBPF guest: ELF to the public segment, `program_hash` dropped, the new `out1..7`, the canonical `input_hash` layout, the EVM guest untouched → Task 4 (and the EVM guest appears in no task's file list, which is the point). §9.5 the cost model and the tier projection → Task 5 Steps 1–3. §9.6 privacy → Task 5 Step 3. §9.7 vendoring, `deploy/sync-zkvm.sh`, M5 unaffected → Global Constraints and Task 5's docs. §9.8's rulings are all either implemented or recorded.

**Placeholder scan.** No "TBD", no "handle edge cases", no "similar to Task N". The one place this plan deliberately does not write the code out is Task 2 Step 3 and Task 3's mirroring, where the instruction is "`tables/input.rs` with these exact identifiers substituted" — that is a copy with a named source and a named substitution list, not a placeholder, and the AIR body it produces is written out in full anyway. The numbers Task 5 records cannot be known before the run, which is why Step 2 states the **rule** that decides the test's fate rather than the outcome.

**Type consistency.** `hash::{public_digest, public_digest_rows, public_digest_row_count}` (T1) are used by T2's `build_traces_salted` and `verify_public` and by T2's e2e tests. `isa::SYS_READ_PUBLIC`, `emulator::{Syscall::ReadPublic, ExecError::PublicIndex, execute(.., public, ..)}`, `asm::ops::read_public`, `guest_sdk::read_public` (T1) are used by T2's `guests::public_echo`, T3's `setup_with_public` and T4's guest `main`. `pv::{PUB0, NUM}` (T1) is read by T2's AIR pin, T2's e2e test, T3's test (5) and T2's `verify_public`. `tables::public::{col, MIN_LOG_HEIGHT, MAX_LOG_HEIGHT, public_log_height, read_counts, public_trace, PublicAir}` (T2) is used by T2's tables test, T3's every test and T2's `check_declared_heights`. `Proof::public_log_height`, `Traces::{public, public_log_height}`, `Machine::{verify_public, verifier_key/6}`, `check_declared_heights/7`, `max_constraint_degrees/7`, `VerifyError::PublicHeight`, `ProveError::{PublicTooLong, PublicTooLarge}` (T1/T2) are used by T3's tests (6), (6b) and T5's exit test. `sbpf_core::abi::{canonical_input_hash, public_output/4, decode_input/3, run_call/6, run_call_with/6}` and `sbpf::SbpfCall::{public_words, input_words, expected}` (T4) are used by T4's tests and T5's exit test. The name is `read_public` everywhere — SDK, asm helper, cursor argument — and `public_log_height` everywhere, never `pub_log_height`.
