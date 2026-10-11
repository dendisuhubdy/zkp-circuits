# rVM `MODQ` Chip (Private Multisig Phase 3) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make Dilithium2 verification cheap inside an rVM proof. An optional `modq` chip (syscall `MODQ = 8`) runs the ring arithmetic. `NTT`, `INTT`, `DOT4` and `MSUB4` each cost one cpu row and one 1 024-row block. Guest-side trims of the remaining software then take one verification from 880 102 cycles to about 85 k, and the `msauth` guest at `M_MAX = 3` to about 253 k. The gate is tier 18 only: never 19 or 20. Task 8 measures; if `M = 3` misses tier 18, `M_MAX` drops to 2 and `UNIFORM` is phase 3b.
**Architecture:** `research/src/modq.rs` is the reference semantics. Its outputs are canonical in `[0, q)`; its inputs are any words below `2^24`, read mod `q`. The emulator calls it on `SYS_MODQ`. `research/src/tables/modq.rs` proves each call in a 1 024-row block: exact `O + K·q = α·U + β·V (+γ)` identities with byte limbs on `RANGE8`, a chip-internal `MODQ_WIRE` permutation bus between transform stages, and its own `MEMORY` traffic. The cpu gains one appended column, `SYS_MODQ`, and looks the call up on `bus::MODQ`, as `SHA256` does. The table is optional per proof (`modq_log_height = 0` means absent). The machine API is additive (`*_with_modq`), so recursion and the fullnode sync anchor compile unchanged. `dilithium-core` reaches the ring through a `Ring` trait: `SoftRing` on the host, `SyscallRing` in guests, and `HostModq` (the emulator's semantics) for differential tests.
**Tech Stack:** Rust 1.98.1 (`cargo +1.98.1`), Plonky3 0.7 (`p3-air`, `p3-lookup`, `p3-batch-stark`) in `research/`, `riscv32im` guests built only by `rand-guest build`, `guest-sdk`, `crystals-dilithium = "=2.0.0"` as the oracle.
**Spec:** `docs/superpowers/specs/2026-10-11-rvm-modq-chip-design.md` (parent: `docs/superpowers/specs/2026-10-11-private-multisig-design.md` §6–§7)
## Global Constraints

- Worktree `~/rand-worktrees/circuits-private-multisig`, branch `feat/private-multisig`. Run `ListAgents` first and claim the thread before you write anything.
  - The phase-2 (`msauth`) session commits on this same branch. Tasks 1–5 touch no phase-2 file. Tasks 6–8 edit `guests-compiled/msauth` and `research/tests/msauth.rs`, so start them only after phase 2's last commit.
  - rVM phase 4 (`~/rand-worktrees/circuits-phase4`, `feat/rvm-phase4-spans`) owns `recursion/`.
- **Never edit any file under `recursion/`** except Task 9's pinned artefacts. Do that only after rVM phase 4 (`feat/rvm-phase4-spans`) has been **merged** into this branch: `git merge`, never `git rebase`. The branch carries merge `26f547e` (circuits `feat/scan-compact` `56b7061`, the fullnode `CIRCUITS_PIN` base), and it must survive. Circuits `main` may lag phase 4; check, don't assume.
- Every command runs from `research/` with `cargo +1.98.1`. Guests are built only by `cd rand-guest && cargo +1.98.1 run -- build <dir> --out <bin> --max-words 65535`.
- The disk is nearly full. Before the first build of each task, check `df -h ~` shows ≥ 20 GB free. If it does not, stop and report rather than deleting anything outside this worktree's `target/`.
- Syscall number **8** (`7` is `POSEIDON2_LEN`).
  - `a0` = arena base (a word address). `a1 = op | OUT<<8 | A<<16 | B<<24`, with `op` ∈ {0 `NTT`, 1 `INTT`, 2 `DOT4`, 3 `MSUB4`} and 5-bit poly offsets.
  - Reserved bits are zero.
  - `A = B = 0` for transforms.
- `q = 8 380 417`, `n⁻¹ = 8 347 681`, `ζ_k = 1753^{brv8(k)} mod q` (`= ZETAS[k]·2^{−32} mod q`).
  - Inputs must be `< 2^24`; the emulator refuses others with `ModqCoefficient`.
  - Outputs are canonical.
  - Reads are at slot 0, writes at slot 1.
- **Append-only edits to shared lists:**
  - cpu columns after `GD0..3`
  - buses after `BLIND` (the catalogue's last entry)
  - `chips()` order: `…, Keccak?, Sha256?, Modq?, Public`
  - `CycleEvent` gains `modq: Option<Box<ModqCall>>`; boxed, because one call carries up to 2 304 words.
- **These existing signatures stay byte-identical** and delegate with `modq_log_height = 0`:
  - `machine::chips(tier, k, s)`
  - `machine::check_declared_heights(tier, p, i, k, s, pub, mem)`
  - `Machine::log_ext_degrees(…7…)`
  - `Machine::verifier_key(tier, p, i, k, s, pub)`
  - `machine::max_constraint_degrees(…7…)`
  - `gas::gas_max(tier, k, s)`
  - New siblings carry `_with_modq`.
- **Tier 18 is the only target** (ruling): never add 19 to `TIERS`, never accept a tier-20 `msauth`.
- This is a constraint set: every verifier key changes, so it ships only with a chain cut. Tasks 4 and 9 re-pin, never by guessing: each pin is read off the failing assertion.

## Review Focus

1. **Equality with `crystals-dilithium` (spec §3.6).** `w1` entering `use_hint` must equal the reference's `caddq(w1)` word for word.
   - `chknorm` must run on the **centred** `z` before canonicalisation.
   - Owned by Task 6's three-backend `ours()`. Also owned by Task 7's `fused_unpack_matches_the_reference_unpack_and_chknorm`.
2. **`MODQ_WIRE` balance.** Each `(CLK, stage, index)` key is produced once and consumed once per real block, and `CLK` is unique per real block because `MODQ` has no `MULT`. Owned by Task 5's `modq_wire_value_swap_is_rejected` and `modq_padding_block_made_real_is_rejected`.
3. **Range checks are plain bytes** (no shifted-limb lookups).
   - `D = q − 1 − O` makes outputs canonical.
   - `K` has four bytes, so no identity can wrap mod `p`.
   - Owned by Task 3's tamper tests and by Task 5's `modq_non_canonical_output_is_rejected` and `modq_input_limb_out_of_range_is_rejected`.
4. **Emulator ⊆ AIR.** Every run the emulator admits must be provable. `modq::call` refuses exactly the aliasing, reserved-bit, unused-operand, base and coefficient cases that the memory table, the `A1` decomposition or the limbs make unprovable, and nothing more. Owned by Task 2's refusal tests. The reverse direction (the AIR refuses what the emulator refuses) is owned by Task 5's AIR-level forgeries.
5. **Additive API.** `git diff main -- research/src/machine.rs` must show the six signature lines above unchanged. Owned by Task 4, Step 6.
6. **Shape leak.** The `msauth` prover pins the tier to `tier(M_MAX)` and floors the modq, keccak and memory heights. Fullnode admission pins every height. Owned by Task 4's `height_floors_pin_the_declared_shape` and Task 8's `proof_shape_is_the_same_for_every_m`.
7. **Each cheating test is red before it is green.** Every AIR-level forgery is accepted with only its targeted defence switched off and rejected with it on (Task 5).

---

### Task 1: Host reference semantics, `research/src/modq.rs`

**Files:**
- Create: `research/src/modq.rs`
- Modify: `research/src/lib.rs` (`pub mod modq;`)
- Create: `research/tests/modq.rs`
- Create: `research/tests/modq_reference.rs` (the differential against `dilithium-core`; kept out of `tests/modq.rs` so that file stays vendorable, and out of the phase-2 session's `tests/dilithium.rs`)

**Interfaces:**
- Consumes: nothing new.
- Produces (`rand_zkvm::modq`):
  ```rust
  pub const Q: u32 = 8_380_417;
  pub const N: usize = 256;
  pub const N_INV: u32 = 8_347_681;
  pub const INPUT_BOUND: u32 = 1 << 24;
  pub type Poly = [u32; N];
  pub fn zeta(k: usize) -> u32;                       // 1753^{brv8(k)} mod q, k in 1..256
  pub fn ntt(a: &mut Poly);                           // inputs < 2^24, outputs canonical
  pub fn intt(a: &mut Poly);                          // exact inverse of ntt, n⁻¹ included
  pub fn ntt_stages(a: &Poly) -> [Poly; 9];           // [0] = input as given, [8] = ntt(a)
  pub fn intt_stages(a: &Poly) -> [Poly; 9];          // [0] = input as given, [8] = intt(a)
  pub fn dot4(a: &[Poly; 4], b: &[Poly; 4]) -> Poly;  // out[c] = Σ a[k][c]·b[k][c] mod q
  pub fn msub4(w: &mut [Poly; 4], c: &Poly, t: &[Poly; 4]); // w[k][c] = w[k][c] − c[c]·t[k][c] mod q
  #[derive(Clone, Copy, Debug, PartialEq, Eq)] pub enum Op { Ntt = 0, Intt = 1, Dot4 = 2, Msub4 = 3 }
  #[derive(Clone, Copy, Debug, PartialEq, Eq)] pub struct Args { pub op: Op, pub out: u32, pub a: u32, pub b: u32 }
  impl Args { pub fn encode(self) -> u32; pub fn decode(a1: u32) -> Option<Args>; pub fn aliasing_ok(self) -> bool; }
  #[derive(Clone, Copy, Debug, PartialEq, Eq)] pub enum ModqError { Args(u32), Alias(u32), Coefficient { addr: u32, value: u32 } }
  #[derive(Clone, Debug, PartialEq, Eq)] pub struct CallIo { pub args: Args, pub inputs: Vec<Poly>, pub reads: Vec<(u32, u32)>, pub writes: Vec<(u32, u32)> }
  pub fn call(base: u32, a1: u32, read: impl FnMut(u32) -> u32) -> Result<CallIo, ModqError>;
  ```
  - `CallIo::inputs` order: `NTT`/`INTT` `[p]`; `DOT4` `[a0..a3, b0..b3]`; `MSUB4` `[w0..w3, c, t0..t3]`.
  - `reads`/`writes` are `(word address, value)`. Reads cover every input word, each address once. Writes cover every output word, each address once.

- [ ] **Step 1: Write the failing tests** (`research/tests/modq.rs`)

```rust
//! `MODQ` (private multisig phase 3): the host reference semantics, the emulator syscall, the chip
//! standalone, and the machine wiring. Free of `dilithium-core` so the fullnode can vendor it.
use rand_zkvm::modq::{self, Args, ModqError, Op, Poly, Q};

pub fn rng(seed: u64) -> impl FnMut() -> u64 {
    let mut x = seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1;
    move || { x ^= x << 13; x ^= x >> 7; x ^= x << 17; x }
}
pub fn poly(next: &mut impl FnMut() -> u64, bound: u32) -> Poly {
    core::array::from_fn(|_| (next() % bound as u64) as u32)
}
fn pow(b: u64, mut e: u64) -> u64 {
    let (mut r, mut b) = (1u64, b % Q as u64);
    while e > 0 { if e & 1 == 1 { r = r * b % Q as u64; } b = b * b % Q as u64; e >>= 1; }
    r
}
fn brv8(k: usize) -> u64 { (k as u8).reverse_bits() as u64 }

#[test]
fn zeta_is_1753_to_the_bit_reversed_index() {
    for k in 1..256 { assert_eq!(modq::zeta(k) as u64, pow(1753, brv8(k)), "k = {k}"); }
}

#[test]
fn ntt_evaluates_at_the_odd_powers_of_psi() {
    let mut next = rng(1);
    let a = poly(&mut next, Q);
    let mut hat = a;
    modq::ntt(&mut hat);
    for i in (0..256).step_by(17) {
        let r = pow(1753, 2 * brv8(i) + 1);
        let (mut acc, mut x) = (0u64, 1u64);
        for j in 0..256 { acc = (acc + a[j] as u64 * x) % Q as u64; x = x * r % Q as u64; }
        assert_eq!(hat[i] as u64, acc, "index {i}");
    }
}

#[test]
fn intt_inverts_ntt_and_every_output_is_canonical() {
    let mut next = rng(2);
    for _ in 0..50 {
        let a = poly(&mut next, Q);
        let mut x = a;
        modq::ntt(&mut x);
        assert!(x.iter().all(|&c| c < Q));
        modq::intt(&mut x);
        assert_eq!(x, a);
    }
}

#[test]
fn inputs_below_2_pow_24_are_read_mod_q() {
    let mut next = rng(3);
    let raw = poly(&mut next, modq::INPUT_BOUND);
    let reduced: Poly = core::array::from_fn(|i| raw[i] % Q);
    let (mut x, mut y) = (raw, reduced);
    modq::ntt(&mut x);
    modq::ntt(&mut y);
    assert_eq!(x, y);
    let (mut x, mut y) = (raw, reduced);
    modq::intt(&mut x);
    modq::intt(&mut y);
    assert_eq!(x, y);
}

#[test]
fn dot4_and_msub4_match_schoolbook_mod_q() {
    let mut next = rng(4);
    let a: [Poly; 4] = core::array::from_fn(|_| poly(&mut next, modq::INPUT_BOUND));
    let b: [Poly; 4] = core::array::from_fn(|_| poly(&mut next, modq::INPUT_BOUND));
    let c = poly(&mut next, modq::INPUT_BOUND);
    let d = modq::dot4(&a, &b);
    let mut w = a;
    modq::msub4(&mut w, &c, &b);
    let q = Q as u64;
    for i in 0..256 {
        let want: u64 = (0..4).map(|k| (a[k][i] as u64 % q) * (b[k][i] as u64 % q) % q).sum::<u64>() % q;
        assert_eq!(d[i] as u64, want);
        for k in 0..4 {
            let sub = (c[i] as u64 % q) * (b[k][i] as u64 % q) % q;
            assert_eq!(w[k][i] as u64, (a[k][i] as u64 % q + q - sub) % q);
        }
    }
}

#[test]
fn the_stages_start_at_the_input_and_end_at_the_transform() {
    let mut next = rng(5);
    let a = poly(&mut next, modq::INPUT_BOUND);
    let (s, t) = (modq::ntt_stages(&a), modq::intt_stages(&a));
    let (mut x, mut y) = (a, a);
    modq::ntt(&mut x);
    modq::intt(&mut y);
    assert_eq!((s[0], s[8], t[0], t[8]), (a, x, a, y));
    for p in 1..9 { assert!(s[p].iter().chain(t[p].iter()).all(|&c| c < Q), "stage {p} canonical"); }
}

#[test]
fn args_round_trip_and_reject_every_reserved_bit() {
    for (op, out, a, b) in [(Op::Ntt, 3, 0, 0), (Op::Intt, 31, 0, 0), (Op::Dot4, 8, 0, 4), (Op::Msub4, 0, 8, 4)] {
        let args = Args { op, out, a, b };
        assert_eq!(Args::decode(args.encode()), Some(args));
    }
    for bit in [2u32, 7, 13, 15, 21, 23, 29, 31] {
        assert_eq!(Args::decode(Args { op: Op::Dot4, out: 8, a: 0, b: 4 }.encode() | 1 << bit), None, "bit {bit}");
    }
    assert_eq!(Args::decode(Args { op: Op::Ntt, out: 0, a: 1, b: 0 }.encode()), None, "a transform names one poly");
}

#[test]
fn call_reads_each_input_once_and_refuses_what_the_air_cannot_prove() {
    let base = 0x1000;
    let ram = |a: u32| (a.wrapping_mul(2_654_435_761) >> 9) % modq::INPUT_BOUND;
    let io = modq::call(base, Args { op: Op::Dot4, out: 8, a: 0, b: 4 }.encode(), ram).unwrap();
    assert_eq!((io.inputs.len(), io.reads.len(), io.writes.len()), (8, 2048, 256));
    let mut addrs: Vec<u32> = io.reads.iter().map(|r| r.0).collect();
    addrs.sort();
    addrs.dedup();
    assert_eq!(addrs.len(), 2048, "no address is read twice at one timestamp");
    let dot = Args { op: Op::Dot4, out: 8, a: 0, b: 3 }.encode();
    assert_eq!(modq::call(base, dot, ram), Err(ModqError::Alias(dot)));
    let msub = Args { op: Op::Msub4, out: 0, a: 2, b: 4 }.encode();
    assert_eq!(modq::call(base, msub, ram), Err(ModqError::Alias(msub)));
    let big = |a: u32| if a == base + 7 { 1 << 24 } else { 0 };
    assert_eq!(modq::call(base, 0, big), Err(ModqError::Coefficient { addr: base + 7, value: 1 << 24 }));
    assert_eq!(modq::call(base, 1 << 2, ram), Err(ModqError::Args(1 << 2)));
}
```

Create `research/tests/modq_reference.rs`:

```rust
//! MODQ phase 3, Task 1: the reference semantics agree with dilithium-core mod q.

fn canon(x: i64) -> u32 { x.rem_euclid(rand_zkvm::modq::Q as i64) as u32 }

#[test]
fn modq_agrees_with_the_reference_ntt_invntt_and_montgomery_product_mod_q() {
    use dilithium_core::{ntt, reduce::montgomery_reduce};
    use rand_zkvm::modq;
    let q = modq::Q as i64;
    let mont = (1i64 << 32) % q;                                   // 4 193 792
    let mont_inv = (1..q).find(|x| x * mont % q == 1).unwrap();
    let mut s = 7u64;
    let mut next = move || { s ^= s << 13; s ^= s >> 7; s ^= s << 17; s };
    for _ in 0..40 {
        let a: [i32; 256] = core::array::from_fn(|_| (next() % (2 * q as u64 - 1)) as i32 - (q as i32 - 1));
        let ac: [u32; 256] = core::array::from_fn(|i| canon(a[i] as i64));
        let (mut r, mut m) = (a, ac);
        ntt::ntt(&mut r);
        modq::ntt(&mut m);
        assert_eq!(m, core::array::from_fn(|i| canon(r[i] as i64)), "ntt ≡ reference ntt");
        let (mut r, mut m) = (a, ac);
        ntt::invntt_tomont(&mut r);
        modq::intt(&mut m);
        assert_eq!(core::array::from_fn::<u32, 256, _>(|i| canon(r[i] as i64)),
                   core::array::from_fn(|i| canon(m[i] as i64 * mont)), "invntt_tomont ≡ 2^32 · intt");
        for i in 0..256 {
            let (x, y) = (a[i] as i64, a[255 - i] as i64);
            assert_eq!(canon(montgomery_reduce(x * y) as i64), canon(x * y % q * mont_inv), "pointwise_montgomery ≡ a·b·2^-32");
        }
    }
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd research && cargo +1.98.1 test --release --test modq --test modq_reference`
Expected: compile error, unresolved import `rand_zkvm::modq`.

- [ ] **Step 3: Implement** `research/src/modq.rs`.
  - `zeta(k)`: `pow(1753, (k as u8).reverse_bits())` by square-and-multiply in `u64`.
  - `ntt_stages`: the reference loop of `dilithium-core/src/ntt.rs` (`len = 128 >> p`, `k = 2^p + g`), with `t = ζ_k·v mod q`, `o0 = (u + t) mod q`, `o1 = (u + q − t) mod q` on `u64`. Stage 0 is the input as given; reduce `u`/`v` with `% Q` inside the butterfly only.
  - `intt_stages`: the reference GS loop (`len = 1 << p`, `k = (256 >> p) − 1 − g`, `ζ' = q − ζ_k`): `o0 = (u + v) mod q`, `o1 = ζ'·(u + q − v mod q) mod q`. On stage 7, multiply both outputs by `N_INV` inside the same butterfly. That is the fused scaling the chip uses (spec §3.3).
  - `ntt`/`intt` return `stages[8]`. `dot4`/`msub4` are `u64` schoolbook.
  - `Args::decode`: refuse any bit outside `0..2, 8..13, 16..21, 24..29`, and refuse a transform with `a != 0 || b != 0`.
  - `aliasing_ok`:
    - `DOT4`: `a.abs_diff(b) >= 4`.
    - `MSUB4`: `[out, out+4)`, `[b, b+4)` and `{a}` pairwise disjoint.
  - There is no cap on the highest poly index: 5-bit offsets plus a 4-poly span stay inside `MODQ_SPAN_WORDS` (Review Focus 4).
  - `call`: decode (`Args(a1)`), check aliasing (`Alias(a1)`), read every input word in `CallIo::inputs` order (`Coefficient` on the first word `≥ 2^24`), compute, and list the writes. Spec §3.1 has the address map (`BASE + 256·poly + coefficient`).
  - Add `pub mod modq;` to `lib.rs`.

- [ ] **Step 4: Run to verify it passes.** Same commands. Expected: 8 passed (`modq`), 1 passed (`modq_reference`).

- [ ] **Step 5: Commit**

```bash
git add research/src/modq.rs research/src/lib.rs research/tests/modq.rs research/tests/modq_reference.rs
git commit -m "modq: reference semantics — canonical NTT/INTT/DOT4/MSUB4 mod q, a1 encoding, call(), differential against dilithium-core"
```

### Task 2: The `MODQ = 8` syscall in the emulator

**Files:**
- Modify: `research/src/isa.rs` (append after `SYS_POSEIDON2_LEN`)
- Modify: `research/src/emulator.rs` (`Syscall::Modq`, `ModqCall`, `CycleEvent::modq`, four `ExecError`s, `MODQ_PTR_LIMIT`, the handler; add `modq: None` to every `CycleEvent` literal the compiler flags)
- Modify: `research/src/tables/memory.rs` (`memory_trace` chains `e.modq` accesses)
- Modify: `research/src/machine.rs` (only `mem_accesses` counts `e.modq` accesses; add `modq: None` to any `CycleEvent` literal)
- Modify: `research/src/tables/sha256.rs` and `research/tests/{cheating,emulator,sha256}.rs` (only `modq: None` in every `CycleEvent` literal the compiler flags)
- Modify: `research/src/asm.rs` (`ops::call_modq`)
- Modify: `research/tests/common/mod.rs` (`modq_program`)
- Test: `research/tests/modq.rs`

**Interfaces:**
- Consumes: Task 1's `modq::call`, `CallIo`, `ModqError`, `Args`.
- Produces:
  ```rust
  // isa.rs
  pub const SYS_MODQ: u32 = 8;
  pub const MODQ_SPAN_WORDS: u32 = 256 * 35; // 8 960: the highest word a call can touch is base + 8 959
  // emulator.rs
  pub const MODQ_PTR_LIMIT: u32 = 0x3000_0000 - crate::isa::MODQ_SPAN_WORDS;
  #[derive(Clone, Debug, PartialEq, Eq)]
  pub struct ModqCall { pub clk: u32, pub base: u32, pub a1: u32, pub inputs: Vec<crate::modq::Poly>, pub accesses: Vec<MemAccess> }
  pub enum Syscall { /* … */ Modq { base: u32, a1: u32 } }
  pub struct CycleEvent { /* … */ pub modq: Option<Box<ModqCall>> }
  pub enum ExecError { /* … */ ModqArgs(u32), ModqAlias(u32), ModqPtrOutOfRange(u32), ModqCoefficient { addr: u32, value: u32 } }
  // asm.rs
  pub fn call_modq(base_words: u32, a1: u32) -> Vec<Instr>; // li a7, 8; li a0, base; li a1, a1; ecall
  // tests/common/mod.rs
  pub fn modq_program(calls: &[u32]) -> rand_zkvm::isa::Program; // fills 9 polys at word 0x1000, then one MODQ per a1
  ```
  - `ModqCall::accesses`: every read at slot 0, then every write at slot 1, all `SPACE_RAM`.

- [ ] **Step 1: Write the failing tests.**

Add to `research/tests/common/mod.rs`:

```rust
/// MODQ phase 3: a guest that fills polys 0..9 of an arena at word address `0x1000` with
/// `3 + 7001·i` (some below q, some in [q, 2^24)), then makes one `MODQ` call per `a1`, then halts.
#[allow(dead_code)]
pub fn modq_program(calls: &[u32]) -> rand_zkvm::isa::Program {
    use rand_zkvm::asm::{ops::*, Assembler};
    use rand_zkvm::isa::BranchCond;
    const ARENA_BYTES: i32 = 0x4000;
    let mut a = Assembler::new(0);
    a.extend(li(5, ARENA_BYTES));
    a.extend(li(6, 0));
    a.extend(li(7, 9 * 256));
    a.extend(li(8, 3));
    a.extend(li(9, 7001));
    a.label("fill");
    a.push(sw(5, 8, 0));
    a.push(addi(5, 5, 4));
    a.push(add(8, 8, 9));
    a.push(addi(6, 6, 1));
    a.branch(BranchCond::Ne, 6, 7, "fill");
    for &a1 in calls { a.extend(call_modq(ARENA_BYTES as u32 / 4, a1)); }
    a.extend(halt());
    a.assemble()
}
```

Append to `research/tests/modq.rs`:

```rust
mod common;

mod emulator {
    use super::common::modq_program;
    use rand_zkvm::asm::{ops::*, Assembler};
    use rand_zkvm::emulator::{execute, ExecError, Syscall, MODQ_PTR_LIMIT, SPACE_RAM};
    use rand_zkvm::modq::{self, Args, Op};

    pub const NTT0: u32 = 0;
    pub const INTT1: u32 = 1 | 1 << 8;
    pub const DOT_8_0_4: u32 = 2 | 8 << 8 | 4 << 24;
    pub const MSUB_0_8_4: u32 = 3 | 8 << 16 | 4 << 24;

    fn ram_after_fill(addr: u32) -> u32 {
        let i = addr - 0x1000;
        if i < 9 * 256 { 3 + 7001 * i } else { 0 }
    }

    #[test]
    fn every_op_in_the_emulator_matches_the_host_model() {
        for a1 in [NTT0, INTT1, DOT_8_0_4, MSUB_0_8_4] {
            let e = execute(&modq_program(&[a1]), &[], &[], 1 << 16).unwrap();
            let ev = e.events.iter().find(|e| e.modq.is_some()).expect("one MODQ row");
            assert_eq!(ev.sys, Some(Syscall::Modq { base: 0x1000, a1 }));
            let call = ev.modq.as_ref().unwrap();
            let io = modq::call(0x1000, a1, ram_after_fill).unwrap();
            assert_eq!(call.inputs, io.inputs, "a1 = {a1:#x}");
            let writes: Vec<(u32, u32)> = call.accesses.iter().filter(|a| a.is_write).map(|a| (a.addr, a.value)).collect();
            assert_eq!(writes, io.writes, "a1 = {a1:#x}");
        }
    }

    #[test]
    fn accesses_are_ram_reads_at_slot_0_then_writes_at_slot_1() {
        let e = execute(&modq_program(&[MSUB_0_8_4]), &[], &[], 1 << 16).unwrap();
        let call = e.events.iter().find_map(|e| e.modq.as_ref()).unwrap();
        let first_write = call.accesses.iter().position(|a| a.is_write).unwrap();
        assert_eq!((first_write, call.accesses.len()), (2304, 2304 + 1024));
        assert!(call.accesses.iter().all(|a| a.space == SPACE_RAM && a.slot == a.is_write as u32));
    }

    #[test]
    fn modq_refuses_reserved_bits() {
        let bad = DOT_8_0_4 | 1 << 5;
        assert_eq!(execute(&modq_program(&[bad]), &[], &[], 1 << 16).unwrap_err(), ExecError::ModqArgs(bad));
    }

    #[test]
    fn modq_refuses_overlapping_dot_operands() {
        let bad = Args { op: Op::Dot4, out: 8, a: 0, b: 2 }.encode();
        assert_eq!(execute(&modq_program(&[bad]), &[], &[], 1 << 16).unwrap_err(), ExecError::ModqAlias(bad));
    }

    #[test]
    fn modq_refuses_msub_aliasing() {
        let bad = Args { op: Op::Msub4, out: 0, a: 4, b: 4 }.encode();
        assert_eq!(execute(&modq_program(&[bad]), &[], &[], 1 << 16).unwrap_err(), ExecError::ModqAlias(bad));
    }

    #[test]
    fn modq_refuses_a_coefficient_of_2_pow_24() {
        let mut a = Assembler::new(0);
        a.extend(li(5, 0x4000));
        a.extend(li(8, 1 << 24));
        a.push(sw(5, 8, 12));
        a.extend(call_modq(0x1000, NTT0));
        a.extend(halt());
        let err = execute(&a.assemble(), &[], &[], 1 << 16).unwrap_err();
        assert_eq!(err, ExecError::ModqCoefficient { addr: 0x1003, value: 1 << 24 });
    }

    #[test]
    fn modq_refuses_a_base_past_the_limit() {
        let mut a = Assembler::new(0);
        a.extend(call_modq(MODQ_PTR_LIMIT + 1, NTT0));
        a.extend(halt());
        assert_eq!(execute(&a.assemble(), &[], &[], 1 << 16).unwrap_err(), ExecError::ModqPtrOutOfRange(MODQ_PTR_LIMIT + 1));
        let mut a = Assembler::new(0);
        a.extend(call_modq(MODQ_PTR_LIMIT, NTT0));
        a.extend(halt());
        assert!(execute(&a.assemble(), &[], &[], 1 << 16).is_ok(), "the limit itself is legal");
    }
}
```

- [ ] **Step 2: Run to verify it fails.** `cd research && cargo +1.98.1 test --release --test modq emulator`. Expected: compile error, no `call_modq`, `Syscall::Modq` or `MODQ_PTR_LIMIT`.

- [ ] **Step 3: Implement.**
  - **`isa.rs`:** the two constants, plus a doc comment carrying the ABI in spec §3.1.
  - **`emulator.rs`:**
    - A `SYS_MODQ` branch beside `SYS_SHA256`'s: `let base = arg0; let a1 = mem_val /* the a1 register value the row already reads */;`.
    - Refuse `base > MODQ_PTR_LIMIT`. Call `modq::call(base, a1, |w| *ram.get(&w).unwrap_or(&0))` and map its error to the `ExecError` of the same name.
    - Build `accesses` from `reads` (slot 0) then `writes` (slot 1), and apply the writes to `ram`.
    - Push the `CycleEvent` with `sys: Some(Syscall::Modq { base, a1 })` and `modq: Some(Box::new(ModqCall { clk, base, a1, inputs: io.inputs, accesses }))`, then `clk += 1` and `pc += 4`.
    - Add `modq: None` to every other `CycleEvent` literal the compiler flags. `cargo +1.98.1 test --release --no-run` lists them.
  - **`memory.rs`:** `.chain(e.modq.iter().flat_map(|m| m.accesses.iter()))`.
  - **`machine.rs` `mem_accesses`:** `+ e.modq.as_ref().map_or(0, |m| m.accesses.len())`.
  - **`asm.rs`:** `call_modq`, beside `call_sha256`.

- [ ] **Step 4: Run to verify it passes.** `cargo +1.98.1 test --release --test modq && cargo +1.98.1 test --release --test emulator --test sha256`. Expected: `modq` 15 passed; `emulator` and `sha256` unchanged counts, all pass.

- [ ] **Step 5: Commit**

```bash
git add research/src/isa.rs research/src/emulator.rs research/src/tables/memory.rs research/src/machine.rs research/src/tables/sha256.rs research/src/asm.rs research/tests/common/mod.rs research/tests/modq.rs research/tests/cheating.rs research/tests/emulator.rs research/tests/sha256.rs
git commit -m "emulator: SYS_MODQ = 8 — one row per call, reads at slot 0 then writes at slot 1, refuses reserved bits, aliasing, coefficients >= 2^24 and a base past MODQ_PTR_LIMIT"
```

### Task 3: The `modq` table and its AIR, proved standalone

**Files:**
- Create: `research/src/tables/modq.rs`
- Modify: `research/src/tables/mod.rs` (`pub mod modq;`, plus `bus::MODQ` and `bus::MODQ_WIRE` appended after `bus::BLIND`, the catalogue's last entry)
- Test: `research/tests/modq.rs` (append `mod harness`)

**Interfaces:**
- Consumes: Task 1's `modq::{zeta, ntt_stages, intt_stages, call, CallIo, Args, Op, Poly, Q, N_INV}`; Task 2's `emulator::SPACE_RAM`; `tables::range::RangeCounts`.
- Produces (`rand_zkvm::tables::modq`):
  ```rust
  pub const BLOCK: usize = 1024;
  pub const MIN_LOG_HEIGHT: u8 = 10;
  pub const MAX_LOG_HEIGHT: u8 = 20;
  pub mod pre { pub const IS_FIRST: usize = 0; pub const IS_LAST: usize = 1; pub const STAGE: usize = 2; pub const S_FIRST: usize = 3; pub const S_LAST: usize = 4; pub const JF: usize = 5; pub const VF: usize = 6; pub const JI: usize = 7; pub const VI: usize = 8; pub const ZF: usize = 9; pub const FI: usize = 10; pub const ZI: usize = 11; pub const PK: usize = 12; pub const PC: usize = 13; pub const K_FIRST: usize = 14; pub const K_LAST: usize = 15; pub const WIDTH: usize = 16; }
  pub mod col { pub const IS_REAL: usize = 0; pub const CLK: usize = 1; pub const BASE: usize = 2; pub const A1: usize = 3; pub const IS_NTT: usize = 4; pub const IS_INTT: usize = 5; pub const IS_DOT: usize = 6; pub const IS_MSUB: usize = 7; pub const OUT_BITS: usize = 8; pub const A_BITS: usize = 13; pub const B_BITS: usize = 18; pub const U_L: usize = 23; pub const V_L: usize = 26; pub const W_L: usize = 29; pub const O0_L: usize = 32; pub const D0_L: usize = 35; pub const K0_L: usize = 38; pub const O1_L: usize = 42; pub const D1_L: usize = 45; pub const K1_L: usize = 48; pub const IDX_U: usize = 52; pub const IDX_V: usize = 53; pub const ADDR_U: usize = 54; pub const ADDR_V: usize = 55; pub const ADDR_W: usize = 56; pub const ADDR_O0: usize = 57; pub const ADDR_O1: usize = 58; pub const WIDTH: usize = 59; }
  pub fn limbs_value(row: &[crate::tables::F], base: usize, n: usize) -> u64; // Σ_{i<n} row[base+i].as_canonical_u64()·256^i (n = 1 reads a whole cell)
  #[derive(Clone, Debug, PartialEq, Eq)] pub struct ModqEvent { pub clk: u32, pub base: u32, pub a1: u32, pub inputs: Vec<crate::modq::Poly> }
  #[derive(Clone, Copy, Debug, Default)] pub struct ModqAir;
  impl ModqAir { pub fn preprocessed_trace_at<Fld: Field>(height: usize) -> RowMajorMatrix<Fld>; }
  pub fn modq_log_height(n_calls: usize) -> u8;               // 0 if n == 0, else max(10, log2_ceil(1024·n))
  pub fn modq_trace(events: &[ModqEvent], log_height: u8, range: &mut RangeCounts) -> RowMajorMatrix<F>;
  #[doc(hidden)] pub fn modq_trace_with_zetas(events: &[ModqEvent], log_height: u8, range: &mut RangeCounts, zeta: &dyn Fn(usize) -> u32) -> RowMajorMatrix<F>;
  // tables/mod.rs, bus
  pub const MODQ: LookupBus<'static> = LookupBus::new("MODQ");                    // cpu → modq: (clk, base, a1)
  pub const MODQ_WIRE: PermutationCheckBus<'static> = PermutationCheckBus::new("MODQ_WIRE"); // (clk, stage, index, value)
  ```

- [ ] **Step 1: Write the failing tests** (append to `research/tests/modq.rs`)

```rust
mod harness {
    use super::common::rejects;
    use super::emulator::{DOT_8_0_4, INTT1, MSUB_0_8_4, NTT0};
    use p3_air::{Air, AirBuilder, BaseAir, PermutationAirBuilder, WindowAccess};
    use p3_batch_stark::{prove_batch, verify_batch, ProverData, StarkInstance};
    use p3_field::{Field, PrimeCharacteristicRing};
    use p3_lookup::{Count, InteractionBuilder};
    use p3_matrix::dense::RowMajorMatrix;
    use rand_zkvm::emulator::SPACE_RAM;
    use rand_zkvm::machine::{make_config, FriProfile, VerifyError};
    use rand_zkvm::modq::{self, CallIo};
    use rand_zkvm::tables::modq::{col, limbs_value, modq_log_height, modq_trace, pre, ModqAir, ModqEvent, BLOCK};
    use rand_zkvm::tables::range::{range_trace, RangeAir, RangeCounts};
    use rand_zkvm::tables::{bus, F};

    #[derive(Clone)]
    struct Asker;
    impl<Fld> BaseAir<Fld> for Asker { fn width(&self) -> usize { 4 } }
    impl<AB: AirBuilder + InteractionBuilder> Air<AB> for Asker where AB::F: Field {
        fn eval(&self, b: &mut AB) {
            let m = b.main();
            let v = |i: usize| -> AB::Expr { m.current(i).unwrap().into() };
            b.assert_bool(v(0));
            bus::MODQ.lookup_key(b, [v(1), v(2), v(3)], Count::bounded(v(0), 1));
        }
    }
    #[derive(Clone)]
    struct MemoryTwin;
    impl<Fld> BaseAir<Fld> for MemoryTwin { fn width(&self) -> usize { 6 } }
    impl<AB: AirBuilder + InteractionBuilder> Air<AB> for MemoryTwin where AB::F: Field {
        fn eval(&self, b: &mut AB) {
            let m = b.main();
            let v = |i: usize| -> AB::Expr { m.current(i).unwrap().into() };
            b.assert_bool(v(0));
            bus::MEMORY.receive(b, [v(1), v(2), v(3), v(4), v(5)], Count::bounded(v(0), 1));
        }
    }
    #[derive(Clone)]
    enum T { S(ModqAir, usize), A(Asker), M(MemoryTwin), R(RangeAir) }
    impl<Fld: Field> BaseAir<Fld> for T {
        fn width(&self) -> usize {
            match self {
                T::S(a, _) => <ModqAir as BaseAir<Fld>>::width(a),
                T::A(a) => <Asker as BaseAir<Fld>>::width(a),
                T::M(a) => <MemoryTwin as BaseAir<Fld>>::width(a),
                T::R(a) => <RangeAir as BaseAir<Fld>>::width(a),
            }
        }
        fn preprocessed_width(&self) -> usize {
            match self {
                T::S(a, _) => <ModqAir as BaseAir<Fld>>::preprocessed_width(a),
                T::R(a) => <RangeAir as BaseAir<Fld>>::preprocessed_width(a),
                _ => 0,
            }
        }
        fn preprocessed_trace(&self) -> Option<RowMajorMatrix<Fld>> {
            match self {
                T::S(_, h) => Some(ModqAir::preprocessed_trace_at(*h)),
                T::R(a) => <RangeAir as BaseAir<Fld>>::preprocessed_trace(a),
                _ => None,
            }
        }
    }
    impl<AB: AirBuilder + PermutationAirBuilder + InteractionBuilder> Air<AB> for T where AB::F: Field {
        fn eval(&self, b: &mut AB) {
            match self { T::S(a, _) => a.eval(b), T::A(a) => a.eval(b), T::M(a) => a.eval(b), T::R(a) => a.eval(b) }
        }
    }

    /// Four calls at clk 11..15 on one deterministic RAM (no call's outputs feed another here).
    pub fn calls() -> Vec<(ModqEvent, CallIo)> {
        let ram = |a: u32| (a.wrapping_mul(2_654_435_761) >> 9) % modq::INPUT_BOUND;
        [NTT0, INTT1, DOT_8_0_4, MSUB_0_8_4].iter().enumerate().map(|(i, &a1)| {
            let io = modq::call(0x1000, a1, ram).unwrap();
            (ModqEvent { clk: 11 + i as u32, base: 0x1000, a1, inputs: io.inputs.clone() }, io)
        }).collect()
    }

    pub fn twin(calls: &[(ModqEvent, CallIo)]) -> RowMajorMatrix<F> {
        let rows: Vec<(u32, u32, u32, bool)> = calls.iter().flat_map(|(ev, io)| {
            io.reads.iter().map(move |&(a, x)| (a, 4 * ev.clk, x, false))
                .chain(io.writes.iter().map(move |&(a, x)| (a, 4 * ev.clk + 1, x, true)))
        }).collect();
        let mut v = F::zero_vec(rows.len().next_power_of_two() * 6);
        for (i, &(addr, ts, val, w)) in rows.iter().enumerate() {
            v[i * 6..(i + 1) * 6].copy_from_slice(&[F::ONE, F::from_u32(SPACE_RAM), F::from_u32(addr), F::from_u32(ts), F::from_u32(val), F::from_bool(w)]);
        }
        RowMajorMatrix::new(v, 6)
    }

    pub fn run(trace: &RowMajorMatrix<F>, range: &RangeCounts, calls: &[(ModqEvent, CallIo)], twin: &RowMajorMatrix<F>) -> Result<(), VerifyError> {
        let mut asker = F::zero_vec(calls.len().next_power_of_two().max(4) * 4);
        for (i, (ev, _)) in calls.iter().enumerate() {
            asker[i * 4..i * 4 + 4].copy_from_slice(&[F::ONE, F::from_u32(ev.clk), F::from_u32(ev.base), F::from_u32(ev.a1)]);
        }
        let asker = RowMajorMatrix::new(asker, 4);
        let range_t = range_trace(range);
        let airs = vec![T::S(ModqAir, trace.values.len() / col::WIDTH), T::A(Asker), T::M(MemoryTwin), T::R(RangeAir)];
        let instances = vec![
            StarkInstance { air: &airs[0], trace, public_values: vec![] },
            StarkInstance { air: &airs[1], trace: &asker, public_values: vec![] },
            StarkInstance { air: &airs[2], trace: twin, public_values: vec![] },
            StarkInstance { air: &airs[3], trace: &range_t, public_values: vec![] },
        ];
        let config = make_config(FriProfile::Test);
        let pd = ProverData::from_instances(&config, &instances);
        let proof = prove_batch(&config, &instances, &pd);
        verify_batch(&config, &airs, &proof, &[vec![], vec![], vec![], vec![]], &pd.common).map_err(|e| VerifyError::Batch(format!("{e:?}")))
    }

    fn built() -> (Vec<(ModqEvent, CallIo)>, RowMajorMatrix<F>, RangeCounts) {
        let c = calls();
        let evs: Vec<ModqEvent> = c.iter().map(|x| x.0.clone()).collect();
        let mut range = RangeCounts::default();
        let t = modq_trace(&evs, modq_log_height(evs.len()), &mut range);
        (c, t, range)
    }

    #[test]
    fn modq_log_height_is_zero_without_calls_and_floors_at_one_block() {
        assert_eq!([0, 1, 2, 3, 18, 36, 54].map(modq_log_height), [0, 10, 11, 12, 15, 16, 16]);
    }

    #[test]
    fn the_trace_writes_exactly_what_the_host_model_computes() {
        let (c, t, _) = built();
        let p = ModqAir::preprocessed_trace_at::<F>(BLOCK);
        for (b, (_, io)) in c.iter().enumerate() {
            let mut got = Vec::new();
            for r in 0..BLOCK {
                let row = &t.values[(b * BLOCK + r) * col::WIDTH..(b * BLOCK + r + 1) * col::WIDTH];
                let pr = &p.values[r * pre::WIDTH..(r + 1) * pre::WIDTH];
                let is_t = row[col::IS_NTT] + row[col::IS_INTT] == F::ONE;
                let w0 = (is_t && pr[pre::S_LAST] == F::ONE) || (row[col::IS_DOT] == F::ONE && pr[pre::K_LAST] == F::ONE);
                let w1 = (is_t && pr[pre::S_LAST] == F::ONE) || row[col::IS_MSUB] == F::ONE;
                if w0 { got.push((limbs_value(row, col::ADDR_O0, 1) as u32, limbs_value(row, col::O0_L, 3) as u32)); }
                if w1 { got.push((limbs_value(row, col::ADDR_O1, 1) as u32, limbs_value(row, col::O1_L, 3) as u32)); }
            }
            got.sort();
            let mut want = io.writes.clone();
            want.sort();
            assert_eq!(got, want, "block {b}");
        }
    }

    #[test]
    fn padding_blocks_are_all_zero_selectors() {
        let c = calls();
        let mut range = RangeCounts::default();
        let t = modq_trace(&[c[0].0.clone()], 11, &mut range);
        for r in BLOCK..2 * BLOCK {
            let row = &t.values[r * col::WIDTH..(r + 1) * col::WIDTH];
            assert!([col::IS_REAL, col::IS_NTT, col::IS_INTT, col::IS_DOT, col::IS_MSUB, col::A1].iter().all(|&i| row[i] == F::ZERO));
        }
    }

    #[test]
    fn the_modq_chip_proves_every_op_standalone() {
        let (c, t, range) = built();
        run(&t, &range, &c, &twin(&c)).unwrap();
    }

    #[test]
    fn a_tampered_output_limb_is_rejected_standalone() {
        let (c, mut t, range) = built();
        t.values[(3 * 128 + 5) * col::WIDTH + col::O0_L] += F::ONE;
        assert!(rejects(|| run(&t, &range, &c, &twin(&c))));
    }

    #[test]
    fn a_memory_value_the_chip_did_not_read_is_rejected_standalone() {
        let (c, t, range) = built();
        let mut tw = twin(&c);
        tw.values[4] += F::ONE;
        assert!(rejects(|| run(&t, &range, &c, &tw)));
    }
}
```

- [ ] **Step 2: Run to verify it fails.** `cd research && cargo +1.98.1 test --release --test modq harness`. Expected: compile error, unresolved `rand_zkvm::tables::modq`.

- [ ] **Step 3: Implement** `research/src/tables/modq.rs` exactly as spec §3.3–§3.5.
  - **Module doc.** Copy the `sha256.rs` structure: block geometry, column layout, why byte limbs, degree, padding, the chip's memory traffic.
  - **`preprocessed_trace_at`.** Fill the 16 columns per row `r` of each 1 024-row block, using spec §3.3's formulae:
    - `ZF = zeta(2^p + g)`.
    - `ZI = q − zeta((256 >> p) − 1 − g)`, times `N_INV` on stage 7.
    - `FI = 1`, or `N_INV` on stage 7.
  - **`eval`.** Emit the eight rule groups of spec §3.4 in order:
    1. booleans, one-hot, the `A1` decomposition, canonical args, block constancy under `(1 − IS_LAST)`;
    2. the two output identities and the two `D` identities, as integer forms with `U = Σ U_L[i]·256^i`, …;
    3. `IDX_*` and `ADDR_*`;
    4. the `DOT4` start and carry, and the `MSUB4` broadcast carry;
    5. `MODQ_WIRE` sends and receives;
    6. five `MEMORY` sends, with `Count::bounded(…, 1)` and `ts = 4·CLK` / `4·CLK + 1`;
    7. `bus::MODQ.table_entry([CLK, BASE, A1], IS_REAL·IS_FIRST)`;
    8. 29 `bus::RANGE8.lookup_key([limb], Count::bounded(IS_REAL, 1))`.
  - **`modq_trace_with_zetas`.** For each event:
    - Transforms: take `ntt_stages`/`intt_stages` of `inputs[0]` and fill row `128·p + b` from stage `p`'s pair and stage `p+1`'s outputs.
    - `DOT4`/`MSUB4`: fill row `4c + k` from `inputs`.
    - Every row: compute `K = (α·U + β·V + γ − O)/q` in `u128`, with spec §3.4's `α0, β0, α1, β1, γ1`, write every limb, and call `range.range8` for each of the 29 limbs.
    - Padding blocks: every selector zero; `D` limbs are those of `q − 1`; no `range8` calls.
  - **`modq_trace`** is `modq_trace_with_zetas(…, &modq::zeta)`.
  - **`modq_log_height`:** `0` for no calls; otherwise `pad_height(1024·n, 1024).trailing_zeros().max(MIN_PRIVATE_TABLE_LOG_HEIGHT)`.

- [ ] **Step 4: Run to verify it passes.** `cargo +1.98.1 test --release --test modq harness`. Expected: 6 passed. This is a release build, so a constraint failure shows as a `verify_batch` error, not a row number. To locate a row, re-run the one test without `--release`, where `p3-batch-stark` checks every constraint per row and panics naming it.

- [ ] **Step 5: Commit**

```bash
git add research/src/tables/modq.rs research/src/tables/mod.rs research/tests/modq.rs
git commit -m "tables::modq: the MODQ chip — 1024-row blocks for NTT/INTT/DOT4/MSUB4, exact O + K·q identities on RANGE8 byte limbs, MODQ_WIRE between stages, its own MEMORY traffic; proves standalone"
```

### Task 4: Wire the chip into the machine — cpu column, optional height, key, gas

**Files:**
- Modify: `research/src/tables/cpu.rs` (append `SYS_MODQ`; `SELECTORS` 31 → 32; rule edits and the trace arm of spec §3.2)
- Modify: `research/src/machine.rs`
- Modify: `research/src/gas.rs`
- Test: `research/tests/modq.rs` (append `mod machine`), `research/tests/verifier_key.rs` (fifth shape and re-pins), `research/tests/tables.rs` (degree pin), `research/tests/gas.rs`

**Interfaces:**
- Consumes: Tasks 2–3.
- Produces:
  ```rust
  // tables/cpu.rs
  pub const SYS_MODQ: usize = GD0 + 4;           pub const WIDTH: usize = SYS_MODQ + 1;   // 283
  // machine.rs
  pub enum Chip { /* … */ Modq(crate::tables::modq::ModqAir, usize) }
  pub fn chips_with_modq(tier: Tier, keccak_log_height: u8, sha256_log_height: u8, modq_log_height: u8) -> Vec<Chip>;
  impl Tier { pub fn max_modq_log_height(self) -> u8 }          // min(t + 10, tables::modq::MAX_LOG_HEIGHT)
  pub struct Traces { /* … */ pub modq: Option<RowMajorMatrix<Val>>, pub modq_log_height: u8 }
  pub struct Proof { /* … after sha256_log_height */ pub modq_log_height: u8, /* … */ }
  pub fn check_declared_heights_with_modq(tier: Tier, program_log_height: u8, input_log_height: u8, keccak_log_height: u8, sha256_log_height: u8, modq_log_height: u8, public_log_height: u8, mem_log_height: u8) -> Result<(), VerifyError>;
  impl Machine {
      pub fn log_ext_degrees_with_modq(&self, tier: Tier, program_log_height: u8, input_log_height: u8, keccak_log_height: u8, sha256_log_height: u8, modq_log_height: u8, public_log_height: u8, mem_log_height: u8) -> Vec<usize>;
      pub fn verifier_key_with_modq(&self, tier: Tier, program_log_height: u8, input_log_height: u8, keccak_log_height: u8, sha256_log_height: u8, modq_log_height: u8, public_log_height: u8) -> Arc<CommonData<Config>>;
  }
  pub fn max_constraint_degrees_with_modq(tier: Tier, program_log_height: u8, input_log_height: u8, keccak_log_height: u8, sha256_log_height: u8, modq_log_height: u8, public_log_height: u8, mem_log_height: u8) -> Vec<usize>;
  pub struct ProveOptions { /* … */ pub min_modq_log_height: u8, pub min_keccak_log_height: u8, pub min_mem_log_height: u8 }   // 0 = no floor; prover-side only; the msauth prover sets all three to their M_MAX values
  pub enum VerifyError { /* … */ ModqHeight }
  pub enum ProveError { /* … */ TooManyModqCalls { calls: usize, log_height: u8 } }
  // gas.rs
  pub const MODQ_GAS: u64 = 168;
  pub fn gas_max_with_modq(tier: Tier, keccak_log_height: u8, sha256_log_height: u8, modq_log_height: u8) -> u64;
  ```
  - The old functions become one-line delegations with `modq_log_height = 0`.
  - The key cache's key becomes the 7-tuple `(tier, p, i, k, s, m, pub)`.

- [ ] **Step 1: Write the failing tests** (append to `research/tests/modq.rs`)

```rust
mod machine {
    use super::common::modq_program;
    use super::emulator::{DOT_8_0_4, INTT1, MSUB_0_8_4, NTT0};
    use rand_zkvm::guests;
    use rand_zkvm::machine::{FriProfile, Machine, ProveOptions, Tier};

    #[test]
    fn a_guest_calling_every_op_proves_and_verifies() {
        let m = Machine::new(FriProfile::Test);
        let p = modq_program(&[NTT0, INTT1, DOT_8_0_4, MSUB_0_8_4]);
        let (proof, exec) = m.prove(&p, &[], &[], Some(Tier(14))).unwrap();
        assert_eq!(exec.events.iter().filter(|e| e.modq.is_some()).count(), 4);
        assert_eq!(proof.modq_log_height, 12, "four 1024-row blocks");
        m.verify(&p.digest(), &proof).unwrap();
    }

    #[test]
    fn a_modq_free_proof_declares_no_modq_table() {
        let m = Machine::new(FriProfile::Test);
        let p = guests::fib(10);
        let (proof, _) = m.prove(&p, &[], &[], Some(Tier(10))).unwrap();
        assert_eq!(proof.modq_log_height, 0);
        assert_eq!(proof.batch.degree_bits.len(), 9, "program, cpu, memory, alu, range, nibble, poseidon2, input, public");
        m.verify(&p.digest(), &proof).unwrap();
    }

    #[test]
    fn height_floors_pin_the_declared_shape() {
        let m = Machine::new(FriProfile::Test);
        let p = modq_program(&[NTT0]);
        let opts = ProveOptions { min_modq_log_height: 13, min_keccak_log_height: 9, min_mem_log_height: 18, ..Default::default() };
        let (proof, _) = m.prove_with_options(&p, &[], &[], Some(Tier(14)), opts).unwrap();
        assert_eq!(proof.modq_log_height, 13, "one call padded to eight blocks");
        assert_eq!(proof.keccak_log_height, 9, "a keccak-free run declares an idle table at the floor");
        assert_eq!(proof.mem_log_height, 18, "above the tier floor t + 2 = 16");
        m.verify(&p.digest(), &proof).unwrap();
    }

    #[test]
    fn the_old_key_api_is_the_modq_free_case_of_the_new_one() {
        let m = Machine::new(FriProfile::Test);
        let a = m.verifier_key(Tier(10), 7, 7, 0, 0, 7);
        let b = m.verifier_key_with_modq(Tier(10), 7, 7, 0, 0, 0, 7);
        assert!(std::sync::Arc::ptr_eq(&a, &b), "one cache slot");
        let c = m.verifier_key_with_modq(Tier(10), 7, 7, 0, 0, 10, 7);
        assert!(!std::sync::Arc::ptr_eq(&a, &c));
        assert_eq!(m.cached_keys(), 2);
        assert_eq!(rand_zkvm::gas::gas_max(Tier(12), 5, 0), rand_zkvm::gas::gas_max_with_modq(Tier(12), 5, 0, 0));
        assert_eq!(Tier(10).max_modq_log_height(), 20);
    }

    #[test]
    fn a_modq_row_costs_modq_gas() {
        let p = modq_program(&[NTT0]);
        let e = rand_zkvm::emulator::execute(&p, &[], &[], 1 << 16).unwrap();
        let row = e.events.iter().find(|e| e.modq.is_some()).unwrap();
        assert_eq!(rand_zkvm::gas::row_gas(row), rand_zkvm::gas::MODQ_GAS);
        assert_eq!(rand_zkvm::gas::gas_max_with_modq(Tier(10), 0, 0, 10) - rand_zkvm::gas::gas_max(Tier(10), 0, 0), rand_zkvm::gas::MODQ_GAS - 1);
    }
}
```

In `research/tests/verifier_key.rs`, add `mlh: u8` to `Shape`, `mlh: 0` to the four existing shapes, and this fifth shape (digests recorded in Step 4):

```rust
        Shape {
            name: "tier 10, one modq block",
            tier: Tier(10),
            plh: program::MIN_LOG_HEIGHT,
            ilh: input::input_log_height(0),
            klh: 0,
            slh: 0,
            mlh: rand_zkvm::tables::modq::modq_log_height(1),
            publh: public::MIN_LOG_HEIGHT,
            want: ("0000000000000000000000000000000000000000000000000000000000000000", "0000000000000000000000000000000000000000000000000000000000000000"),
        },
```

and call `verifier_key_with_modq(s.tier, s.plh, s.ilh, s.klh, s.slh, s.mlh, s.publh)` in `the_verifier_keys_answer_their_known_digests`. The all-zero pair fails on purpose. It is the only literal Step 4 overwrites, with the measured digests, as every other key moves too.

In `research/tests/tables.rs`, append:

```rust
#[test]
fn modq_max_constraint_degree_is_pinned() {
    use rand_zkvm::machine::{max_constraint_degrees_with_modq, Tier};
    let d = max_constraint_degrees_with_modq(Tier(10), 7, 7, 0, 0, 10, 7, 12);
    let modq = d[d.len() - 2];
    assert!(modq <= 4, "modq instance degree {modq}: rule degree 3 plus LogUp count degree, log_quotient 2");
}
```

- [ ] **Step 2: Run to verify it fails.** `cd research && cargo +1.98.1 test --release --test modq machine`. Expected: compile error, no `modq_log_height` on `Proof`, no `verifier_key_with_modq`.

- [ ] **Step 3: Implement.**
  - **`cpu.rs`:** spec §3.2's eight edits, each beside its `SYS_SHA256` twin, with a comment naming it. In `cpu_trace`, a `Some(Syscall::Modq { base, .. })` arm fills `SYS_MODQ = 1`, `HASH_PTR = base` and the `HP0..3`/`HP3_HI` limbs, exactly as the `Sha256` arm does.
  - **`machine.rs`:**
    - `Chip::Modq` in every `match` (`table_width`, `preprocessed_width`, `preprocessed_trace` → `ModqAir::preprocessed_trace_at(h)`, `eval`).
    - `chips_with_modq` pushes `Chip::Modq` after `Sha256` and before `Public`. `Traces::as_slice` and `log_ext_degrees_with_modq` follow the same order.
    - `check_declared_heights_with_modq`: when non-zero, require `MIN_LOG_HEIGHT.max(floor)..=tier.max_modq_log_height()` (else `ModqHeight`).
    - `verify` calls the `_with_modq` forms with `proof.modq_log_height`, and `gas_max_with_modq`.
    - `build_traces_inner` collects `ModqEvent { clk: clk_offset + e.clk, base, a1, inputs }` from `e.modq`, computes the height, floored by `opts.min_modq_log_height` when calls exist or the floor is non-zero, and refuses heights over `20` (`TooManyModqCalls`).
    - `min_keccak_log_height` and `min_mem_log_height` floor the keccak and memory heights the same way. They must still lie inside `check_declared_heights`' ranges; otherwise `build_traces_inner` refuses with the existing `TooManyPermutations`/`TooManyMemoryAccesses`. `pad_absent_hash_tables` is unchanged and **does not** pad modq.
    - Build the modq trace **before** `range_trace`, passing `&mut range`.
  - **`gas.rs`:** `row_gas` adds `MODQ_GAS − 1` for `Syscall::Modq`. `gas_max_with_modq` adds `blocks(modq_log_height, 1024)·(MODQ_GAS − 1)`, and `gas_max` delegates.

- [ ] **Step 4: Run, then re-pin from the failures.**
  - `cargo +1.98.1 test --release --test modq --test tables --test gas`. Expected: all pass (modq: 26 = 8 + 7 + 6 + 5).
  - `cargo +1.98.1 test --release --test verifier_key -- --nocapture`. Expected: it fails, listing five changed shapes. Replace each `want` with the printed `(common, commitment)` pair. Extend the module comment's history with "MODQ (private multisig phase 3): cpu `SYS_MODQ` column, every key moved."
  - Re-run: passes.

- [ ] **Step 5: Run the full suite.** `cargo +1.98.1 test --release 2>&1 | tail -30`. Expected: every test passes except pins this task moved. If `tests/e2e.rs`'s `TIER_10_TEST_PROFILE_BYTES` band fails, re-record it from the printed size; the expected move is ≈ +0.3%, inside the band. Any refused honest proof is a defect: stop and report.

- [ ] **Step 6: Check the additive API.** Run `git diff main -- research/src/machine.rs research/src/gas.rs | grep '^-.*pub fn'`. Expected: no line. The six old signatures are unchanged.

- [ ] **Step 7: Commit**

```bash
git add research/src/tables/cpu.rs research/src/machine.rs research/src/gas.rs research/tests/modq.rs research/tests/verifier_key.rs research/tests/tables.rs research/tests/gas.rs research/tests/e2e.rs
git commit -m "machine: the modq table, optional per proof — cpu SYS_MODQ (283 columns), bus::MODQ, Proof::modq_log_height, the 7-tuple key behind *_with_modq, MODQ_GAS = 168, ProveOptions min_{modq,keccak,mem}_log_height floors; every verifier key re-pinned"
```

### Task 5: The cheating suite — forged blocks consistent everywhere else, each defence switched off then on

The method (pre-flight ruling 1, phase 4's `d95aa5e`): a forgery that dies only because the trace is
inconsistent somewhere else proves nothing about the defence it is named for. So each AIR-level
forgery is made consistent everywhere else: `K`/`D` are recomputed, the later stages' wires are
re-propagated, and the memory and range traces are rebuilt from the forged witness. Then each test
asserts three things:

1. **accepted** standalone with only its targeted defence switched off;
2. **rejected** standalone with it on;
3. **rejected** by the full machine.

Defences outside the modq AIR are the memory table's strict order, the memory table's
read-after-write rule and the `MODQ` lookup. Their tests show the forgery passing the modq AIR with
every defence on, and dying in the machine.

**Files:**
- Modify: `research/src/tables/modq.rs` (`#[doc(hidden)]`: `Defence`, `ModqAirWithout`, `Lie`, `Forged`, `forge_block`)
- Modify: `research/src/modq.rs` (`#[doc(hidden)] call_unchecked`)
- Modify: `research/src/emulator.rs` (`#[doc(hidden)] execute_unchecked_modq`)
- Modify: `research/src/machine.rs` (`#[doc(hidden)] build_traces_forged`)
- Create: `research/tests/common/modq_harness.rs` (Task 3's standalone harness, moved and generalised; `tests/common/mod.rs` gains `pub mod modq_harness;`)
- Modify: `research/tests/modq.rs` (Task 3's `harness` tests call `common::modq_harness`)
- Modify: `research/tests/cheating.rs` (append)

**Interfaces:**
- Consumes: Tasks 1–4.
- Produces:
  ```rust
  // tables/modq.rs — test hooks; nothing in chips() or verify() can reach them
  #[doc(hidden)] #[derive(Clone, Copy, Debug, PartialEq, Eq)]
  pub enum Defence { OutputIdentity, Canonical, InputRange, Wire, DotCarry, MsubCarry, A1Decomposition, CanonicalArgs }
  #[doc(hidden)] #[derive(Clone, Copy, Debug, Default)]
  pub struct ModqAirWithout(pub Option<Defence>);   // None evaluates exactly ModqAir's constraints
  #[doc(hidden)] #[derive(Clone, Copy, Debug, PartialEq, Eq)]
  pub enum Lie {
      None,
      NonCanonicalO0 { block: usize, stage: usize },        // first row of `stage` with K0 >= 1: O0 += q, K0 -= 1
      SwapUV { block: usize, stage: usize },                 // first row of `stage` with U != V: swap them
      ButterflyOutput { block: usize, stage: usize, delta: u32 }, // O0 += delta mod q on the stage's first row, K0 kept
      InputLimbCarry { block: usize },                       // first stage-0 row with U_L[1] >= 1: U_L[0] += 256, U_L[1] -= 1
      ReadValue { block: usize, delta: u32 },                // stage-0 row 0: U += delta mod q (a read memory never held)
      DotCarry { block: usize, coefficient: usize, k: usize, delta: u32 },
      MsubBroadcast { block: usize, coefficient: usize, k: usize, delta: u32 },
      OpAs { block: usize, op: crate::modq::Op },           // recompute the block as `op`, keep A1
      ShiftedZetas,                                          // every block computed with zeta(k % 255 + 1)
      RealPadding { block: usize },                          // IS_REAL = IS_NTT = 1 on a padding block (the zero NTT)
  }
  #[doc(hidden)] pub struct Forged { pub trace: RowMajorMatrix<F>, pub range: RangeCounts, pub accesses: Vec<(u32, Vec<crate::emulator::MemAccess>)> }
  #[doc(hidden)] pub fn forge_block(events: &[ModqEvent], log_height: u8, lie: Lie) -> Forged;
  // modq.rs / emulator.rs — reach the chip with what modq::call refuses (reserved bits, A != 0 on a transform, aliasing); still refuse coefficients >= 2^24
  #[doc(hidden)] pub fn call_unchecked(base: u32, a1: u32, read: impl FnMut(u32) -> u32) -> Result<CallIo, ModqError>;
  #[doc(hidden)] pub fn execute_unchecked_modq(program: &Program, inputs: &[u32], public: &[u32], max_cycles: usize) -> Result<Execution, ExecError>;
  // machine.rs — forges the modq block from the run's own events (clk offset applied), writes the forged accesses into a clone of `exec` so memory_trace records them, and merges the forged RangeCounts into the range trace
  #[doc(hidden)] pub fn build_traces_forged(program: &Program, inputs: &[u32], public: &[u32], salt: [u32; 4], exec: &Execution, tier: Tier, gas_limit: u64, lie: Lie) -> Result<Traces, ProveError>;
  // tests/common/modq_harness.rs
  pub fn events(exec: &rand_zkvm::emulator::Execution) -> Vec<ModqEvent>;
  pub fn run(forged: &Forged, events: &[ModqEvent], off: Option<Defence>) -> Result<(), VerifyError>; // modq (ModqAirWithout(off)) + MODQ asker + permissive memory twin + RangeAir
  ```
  - `forge_block`: `Forged.accesses` lists each event's reads and writes, carrying the forged values.
  - `forge_block`: a lie on a transform row also recomputes every later stage of that block from the lie.
  - `forge_block`: `Forged.range` counts every in-range limb and omits the out-of-range one.

- [ ] **Step 1: Write the failing tests** (append to `research/tests/cheating.rs`)

```rust
// ---- MODQ (private multisig phase 3): each forgery accepted with only its defence off ----------

use rand_zkvm::modq::Op;
use rand_zkvm::tables::modq::{forge_block, modq_log_height, Defence, Lie};

const NTT0: u32 = 0;
const INTT1: u32 = 1 | 1 << 8;
const DOT_8_0_4: u32 = 2 | 8 << 8 | 4 << 24;
const MSUB_0_8_4: u32 = 3 | 8 << 16 | 4 << 24;

fn modq_run(calls: &[u32], unchecked: bool) -> (rand_zkvm::isa::Program, rand_zkvm::emulator::Execution) {
    let p = common::modq_program(calls);
    let e = if unchecked { rand_zkvm::emulator::execute_unchecked_modq(&p, &[], &[], 1 << 16) } else { execute(&p, &[], &[], 1 << 16) };
    (p, e.unwrap())
}

fn machine_rejects(p: &rand_zkvm::isa::Program, e: &rand_zkvm::emulator::Execution, n_calls: usize, lie: Lie) -> bool {
    let m = Machine::new(FriProfile::Test);
    let limit = rand_zkvm::gas::gas_max_with_modq(Tier(14), 0, 0, modq_log_height(n_calls));
    let t = rand_zkvm::machine::build_traces_forged(p, &[], &[], [0u32; 4], e, Tier(14), limit, lie).unwrap();
    rejects(|| { let pr = m.prove_traces(p, &t, Tier(14)); m.verify(&p.digest(), &pr) })
}

/// Pre-flight ruling 1: accepted standalone with only `off` switched off, rejected with it on, and rejected by the machine.
fn off_accepts_on_rejects(calls: &[u32], unchecked: bool, lie: Lie, off: Defence) {
    let (p, e) = modq_run(calls, unchecked);
    let evs = common::modq_harness::events(&e);
    let forged = forge_block(&evs, modq_log_height(evs.len()), lie);
    assert!(common::modq_harness::run(&forged, &evs, Some(off)).is_ok(), "{lie:?} must be accepted with only {off:?} off");
    assert!(rejects(|| common::modq_harness::run(&forged, &evs, None)), "{lie:?} must be rejected with {off:?} on");
    assert!(machine_rejects(&p, &e, calls.len(), lie), "{lie:?} must be rejected by the machine");
}

/// Defences outside the modq AIR: the forgery passes the modq AIR with every defence on, and dies in the machine.
fn passes_the_chip_dies_in_the_machine(calls: &[u32], unchecked: bool, lie: Lie) {
    let (p, e) = modq_run(calls, unchecked);
    let evs = common::modq_harness::events(&e);
    let forged = forge_block(&evs, modq_log_height(evs.len()), lie);
    assert!(common::modq_harness::run(&forged, &evs, None).is_ok(), "{lie:?} passes the modq AIR alone");
    assert!(machine_rejects(&p, &e, calls.len(), lie), "{lie:?} must be rejected by the machine");
}

#[test]
fn modq_honest_traces_pass_and_every_lie_changes_the_witness() {
    let (p, e) = modq_run(&[NTT0, INTT1, DOT_8_0_4, MSUB_0_8_4], false);
    assert!(!machine_rejects(&p, &e, 4, Lie::None), "honest");
    let evs = common::modq_harness::events(&e);
    let honest = forge_block(&evs, 12, Lie::None).trace;
    for lie in [Lie::NonCanonicalO0 { block: 0, stage: 7 }, Lie::SwapUV { block: 0, stage: 3 }, Lie::ButterflyOutput { block: 0, stage: 3, delta: 1 },
                Lie::InputLimbCarry { block: 0 }, Lie::DotCarry { block: 2, coefficient: 17, k: 1, delta: 1 }, Lie::MsubBroadcast { block: 3, coefficient: 17, k: 2, delta: 1 },
                Lie::OpAs { block: 1, op: Op::Ntt }] {
        assert_ne!(forge_block(&evs, 12, lie).trace.values, honest.values, "{lie:?} must change the witness");
    }
}

#[test] fn modq_non_canonical_output_is_rejected() { off_accepts_on_rejects(&[NTT0], false, Lie::NonCanonicalO0 { block: 0, stage: 7 }, Defence::Canonical); }
#[test] fn modq_wire_value_swap_is_rejected() { off_accepts_on_rejects(&[NTT0], false, Lie::SwapUV { block: 0, stage: 3 }, Defence::Wire); }
#[test] fn modq_forged_butterfly_output_is_rejected() { off_accepts_on_rejects(&[NTT0], false, Lie::ButterflyOutput { block: 0, stage: 3, delta: 1 }, Defence::OutputIdentity); }
#[test] fn modq_input_limb_out_of_range_is_rejected() { off_accepts_on_rejects(&[NTT0], false, Lie::InputLimbCarry { block: 0 }, Defence::InputRange); }
#[test] fn modq_dot_carry_tamper_is_rejected() { off_accepts_on_rejects(&[DOT_8_0_4], false, Lie::DotCarry { block: 0, coefficient: 17, k: 1, delta: 1 }, Defence::DotCarry); }
#[test] fn modq_msub_broadcast_tamper_is_rejected() { off_accepts_on_rejects(&[MSUB_0_8_4], false, Lie::MsubBroadcast { block: 0, coefficient: 17, k: 2, delta: 1 }, Defence::MsubCarry); }
#[test] fn modq_op_bit_flip_is_rejected() { off_accepts_on_rejects(&[INTT1], false, Lie::OpAs { block: 0, op: Op::Ntt }, Defence::A1Decomposition); }
#[test] fn modq_reserved_a1_bit_is_rejected() { off_accepts_on_rejects(&[NTT0 | 1 << 5], true, Lie::None, Defence::A1Decomposition); }
#[test] fn modq_ntt_with_nonzero_a_is_rejected() { off_accepts_on_rejects(&[NTT0 | 1 << 16], true, Lie::None, Defence::CanonicalArgs); }

#[test] fn modq_overlapping_dot_operands_die_on_strict_order() { passes_the_chip_dies_in_the_machine(&[2 | 8 << 8 | 2 << 24], true, Lie::None); }
#[test] fn modq_memory_read_mismatch_is_rejected() { passes_the_chip_dies_in_the_machine(&[NTT0], false, Lie::ReadValue { block: 0, delta: 1 }); }
#[test] fn modq_wrong_zeta_block_is_rejected() { let (p, e) = modq_run(&[NTT0], false); assert!(machine_rejects(&p, &e, 1, Lie::ShiftedZetas), "ZF is preprocessed, bound by the verifier key"); }
#[test] fn modq_padding_block_made_real_is_rejected() { let (p, e) = modq_run(&[NTT0, INTT1, NTT0], false); assert!(machine_rejects(&p, &e, 3, Lie::RealPadding { block: 3 }), "a MODQ entry no cpu row asks for"); }

#[test]
fn modq_row_without_a_modq_table_is_rejected() {
    let (p, e) = modq_run(&[NTT0], false);
    let m = Machine::new(FriProfile::Test);
    let mut t = build_traces_salted(&p, &[], &[], [0u32; 4], &e, Tier(14), rand_zkvm::gas::gas_max_with_modq(Tier(14), 0, 0, 10)).unwrap();
    t.modq = None;
    t.modq_log_height = 0;
    assert!(rejects(|| { let pr = m.prove_traces(&p, &t, Tier(14)); m.verify(&p.digest(), &pr) }));
}

#[test]
fn modq_heights_outside_the_flat_range_are_rejected_before_any_key() {
    use rand_zkvm::machine::VerifyError;
    let prover = Machine::new(FriProfile::Test);
    let p = common::modq_program(&[NTT0]);
    let (proof, _) = prover.prove(&p, &[], &[], Some(Tier(14))).unwrap();
    let idx = proof.batch.degree_bits.len() - 2;
    for bad in [9u8, 21] {
        let mut pr: rand_zkvm::machine::Proof = postcard::from_bytes(&proof.to_bytes()).unwrap();
        pr.modq_log_height = bad;
        pr.batch.degree_bits[idx] = bad as usize + 1;
        let verifier = Machine::new(FriProfile::Test);
        assert!(matches!(verifier.verify(&p.digest(), &pr), Err(VerifyError::ModqHeight)), "height {bad}");
        assert_eq!(verifier.cached_keys(), 0, "the range check precedes the verifier key");
    }
}
```

- [ ] **Step 2: Run, and see it red.** `cd research && cargo +1.98.1 test --release --test cheating modq`. Expected: compile errors for `forge_block`, `Defence`, `Lie`, `build_traces_forged`, `execute_unchecked_modq` and `common::modq_harness`. That is the red phase. Do not weaken any assertion to make it pass.

- [ ] **Step 3: Implement the hooks.**
  - **`ModqAir::eval`** becomes `eval_minus(b, None)`. `ModqAirWithout(Some(d))` calls `eval_minus(b, Some(d))`, which skips exactly one constraint group:

    | `Defence` | constraints it skips |
    |---|---|
    | `OutputIdentity` | the two `O + qK` identities |
    | `Canonical` | the two `D` identities and their six `RANGE8` lookups |
    | `InputRange` | the nine `U/V/W` lookups |
    | `Wire` | the four `MODQ_WIRE` interactions |
    | `DotCarry` | rule 4's two `DOT4` lines |
    | `MsubCarry` | rule 4's `MSUB4` line |
    | `A1Decomposition` | the `A1` identity |
    | `CanonicalArgs` | `T·A = T·B = 0` |

    `chips()` still builds `ModqAir`. Add a unit test in `tables/modq.rs` that `ModqAirWithout(None)` and `ModqAir` give the same symbolic constraints (`p3_batch_stark::symbolic::get_symbolic_constraints` equal).
  - **`forge_block`.** Start from `modq_trace`'s per-event witness, apply the lie, then re-derive `K`, `D`, the later stages and the memory writes. It uses `call_unchecked`'s decoding for the `A1` bits: valid fields only, reserved bits ignored.
  - **`build_traces_forged`.** Identical to `build_traces_inner`, except the modq trace and its range counts come from `forge_block` over the clk-offset events, and `exec` is cloned with each `ModqCall::accesses` replaced by the forged ones before `memory_trace`.
  - **`call_unchecked` / `execute_unchecked_modq`** skip only the `Args`/`Alias` refusals.
  - **The harness.** Move Task 3's `mod harness` items (`Asker`, `MemoryTwin`, `T`) into `tests/common/modq_harness.rs`. `T::S` holds a `ModqAirWithout`. `run` builds the twin from `forged.accesses` and the range trace from `forged.range`. Repoint Task 3's tests at it.

- [ ] **Step 4: Run to green.** `cargo +1.98.1 test --release --test cheating modq && cargo +1.98.1 test --release --test modq`.
  - Expected: 16 `modq` cheating tests pass, and `tests/modq.rs` still passes.
  - If an "accepted with only X off" assertion fails, the forgery is inconsistent somewhere else. Fix `forge_block`, never the assertion.
  - If a "rejected with X on" or "rejected by the machine" assertion fails, it is a soundness bug. Fix the AIR (Task 3/4 code) with a comment naming the test, and leave the test unchanged.

- [ ] **Step 5: Run** `cargo +1.98.1 test --release --test cheating`. Expected: the previous count plus 16, all pass.

- [ ] **Step 6: Commit**

```bash
git add research/src research/tests/cheating.rs research/tests/common research/tests/modq.rs
git commit -m "cheating: MODQ forgeries consistent everywhere else (forge_block, build_traces_forged) — each accepted with only its defence off and rejected with it on: canonical O+q, wire swap, butterfly, input limb, DOT carry, MSUB broadcast, op flip, reserved a1 bit, NTT with A != 0; DOT aliasing dies on strict order"
```

### Task 6: `dilithium-core` behind a `Ring` trait; guests on `SyscallRing`

Start after phase 2's last commit on this branch (`git log -1 -- guests-compiled/msauth research/tests/msauth.rs`). Claim the thread first.

**Files:**
- Create: `guests-compiled/dilithium-core/src/ring.rs`
- Modify: `guests-compiled/dilithium-core/src/{lib.rs,verify.rs}`
  - The phase-1 body moves verbatim to `verify_reference`.
  - The new `verify_with` uses the arena.
- Modify: `guest-sdk/src/lib.rs` (`SyscallRing`, behind the `dilithium` feature)
- Modify: `research/src/dilithium_host.rs` (`HostModq`)
- Modify: `guests-compiled/dilithium-verify/src/main.rs`, `guests-compiled/msauth/src/main.rs` (a `.bss` static `Arena`, `verify_with(&mut SyscallKeccak, &mut SyscallRing, …)`)
- Create (by `rand-guest build`): `guests-compiled/bin/{dilithium-verify,msauth}.bin` and `.bin.sha256`
- Test: `research/tests/dilithium.rs`

**Interfaces:**
- Consumes: Task 1's `rand_zkvm::modq`; Task 4's machine (for the guest runs).
- Produces (`dilithium_core::ring`):
  ```rust
  pub const ARENA_POLYS: usize = 21;
  pub mod slot { pub const Z: usize = 0; pub const ROW: usize = 4; pub const T1: usize = 8; pub const W: usize = 12; pub const C: usize = 16; pub const H: usize = 17; }
  #[repr(C, align(4))] pub struct Arena { pub p: [[u32; 256]; ARENA_POLYS] }
  impl Arena { pub const fn new() -> Self; }
  pub trait Ring {
      fn ntt(&mut self, ar: &mut Arena, p: usize);
      fn intt(&mut self, ar: &mut Arena, p: usize);
      fn dot4(&mut self, ar: &mut Arena, out: usize, a: usize, b: usize);
      fn msub4(&mut self, ar: &mut Arena, out: usize, c: usize, t: usize);
  }
  pub const fn modq_a1(op: u32, out: usize, a: usize, b: usize) -> u32;   // op | out<<8 | a<<16 | b<<24
  pub struct SoftRing;  impl Ring for SoftRing
  // verify.rs
  pub fn verify_with<K: Keccak, R: Ring>(k: &mut K, r: &mut R, ar: &mut Arena, pk: &[u8; 1312], m: &[u8], sig: &[u8; 2420]) -> bool;
  pub fn verify<K: Keccak>(k: &mut K, pk: &[u8; 1312], m: &[u8], sig: &[u8; 2420]) -> bool;            // verify_with(SoftRing, stack Arena)
  pub fn verify_reference<K: Keccak>(k: &mut K, pk: &[u8; 1312], m: &[u8], sig: &[u8; 2420]) -> bool;  // the phase-1 Montgomery path, verbatim
  // guest-sdk
  pub struct SyscallRing;  impl dilithium_core::ring::Ring for SyscallRing
  // research/src/dilithium_host.rs
  pub struct HostModq;  impl dilithium_core::ring::Ring for HostModq   // via rand_zkvm::modq
  ```

- [ ] **Step 1: Write the failing tests.** In `research/tests/dilithium.rs`, change `ours` so every existing test checks all three backends:

```rust
fn ours(pk: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    use dilithium_core::ring::{Arena, SoftRing};
    use rand_zkvm::dilithium_host::HostModq;
    let (pk, sig) = (pk.try_into().unwrap(), sig.try_into().unwrap());
    let reference = dilithium_core::verify_reference(&mut HostKeccak, pk, msg, sig);
    let soft = dilithium_core::verify_with(&mut HostKeccak, &mut SoftRing, &mut Box::new(Arena::new()), pk, msg, sig);
    let chip = dilithium_core::verify_with(&mut HostKeccak, &mut HostModq, &mut Box::new(Arena::new()), pk, msg, sig);
    assert_eq!((soft, chip), (reference, reference), "three backends disagree");
    assert_eq!(dilithium_core::verify(&mut HostKeccak, pk, msg, sig), reference);
    reference
}
```

and append:

```rust
#[test]
fn soft_ring_and_host_modq_agree_op_by_op() {
    use dilithium_core::ring::{modq_a1, slot, Arena, Ring, SoftRing};
    use rand_zkvm::dilithium_host::HostModq;
    let mut s = 11u64;
    let mut next = move || { s ^= s << 13; s ^= s >> 7; s ^= s << 17; s };
    let mut a = Box::new(Arena::new());
    for p in a.p.iter_mut() { for c in p.iter_mut() { *c = (next() % (1 << 24)) as u32; } }
    let mut b = Box::new(Arena { p: a.p });
    for (soft, host) in [
        (|r: &mut SoftRing, x: &mut Arena| r.ntt(x, slot::Z)) as fn(&mut SoftRing, &mut Arena),
        |r, x| r.intt(x, slot::W),
        |r, x| r.dot4(x, slot::W, slot::ROW, slot::Z),
        |r, x| r.msub4(x, slot::W, slot::C, slot::T1),
    ].into_iter().zip([
        (|r: &mut HostModq, x: &mut Arena| r.ntt(x, slot::Z)) as fn(&mut HostModq, &mut Arena),
        |r, x| r.intt(x, slot::W),
        |r, x| r.dot4(x, slot::W, slot::ROW, slot::Z),
        |r, x| r.msub4(x, slot::W, slot::C, slot::T1),
    ]) {
        soft(&mut SoftRing, &mut a);
        host(&mut HostModq, &mut b);
        assert_eq!(a.p, b.p);
    }
    assert_eq!(modq_a1(2, slot::W, slot::ROW, slot::Z), rand_zkvm::modq::Args { op: rand_zkvm::modq::Op::Dot4, out: 12, a: 4, b: 0 }.encode());
}
```

and in `the_guest_verifies_like_the_host_and_reports_its_cycles`, after the `perms` line:

```rust
        let modq_calls = exec.events.iter().filter(|e| matches!(e.sys, Some(Syscall::Modq { .. }))).count();
        assert_eq!(modq_calls, 18, "9 NTT + 4 DOT4 + 1 MSUB4 + 4 INTT");
```

- [ ] **Step 2: Run to verify it fails.** `cd research && cargo +1.98.1 test --release --test dilithium`. Expected: compile error, no `dilithium_core::ring` or `verify_reference`.

- [ ] **Step 3: Implement.**
  - **`ring.rs`.** `SoftRing` is the canonical `u64` algorithm of spec §3.3: the same loops as `research/src/modq.rs`, re-typed for `no_std` with no heap. `ZETA` is a `const [u32; 256]` computed by a `const fn` from 1753.
  - **`verify_with`.** The phase-1 `verify` with the ring section replaced:
    1. Unpack `t1` into `ar.p[T1..T1+4]` as canonical `t1 << 13`.
    2. After `unpack_sig` and `l_chknorm` on the centred `z` (unchanged), write `[z]` into `ar.p[Z..Z+4]`.
    3. `challenge` writes `c` with `−1 ↦ q − 1` into `ar.p[C]`.
    4. Call `r.ntt` ×9; then `matrix_expand_row` into `ar.p[ROW..ROW+4]` followed by `r.dot4(ar, W + i, ROW, Z)` per row; then `r.msub4(ar, W, C, T1)` and `r.intt` ×4.
    5. Run `use_hint` on `ar.p[W..W+4]` read as `i32`. There is no `caddq` or `reduce32`.
  - **`SyscallRing`:** `ecall` with `a7 = 8`, `a0 = (ar as *mut Arena as u32) / 4` and `a1 = modq_a1(…)`. Add a `// SAFETY:` comment naming the arena span, and a `debug_assert!` that every index span stays `< ARENA_POLYS`.
  - **`HostModq`:** copy polys in and out of `rand_zkvm::modq`.
  - **Guests:** a `static mut ARENA: Arena = Arena::new();` reached through one `unsafe { &mut *core::ptr::addr_of_mut!(ARENA) }`.
  - Rebuild both guests:

```bash
cd rand-guest && cargo +1.98.1 run -- build ../guests-compiled/dilithium-verify --out ../guests-compiled/bin/dilithium-verify.bin --max-words 65535
cargo +1.98.1 run -- build ../guests-compiled/msauth --out ../guests-compiled/bin/msauth.bin --max-words 65535
```

- [ ] **Step 4: Run to verify it passes.** `cd research && cargo +1.98.1 test --release --test dilithium && cargo +1.98.1 test --release --test msauth && cd ../rand-guest && cargo +1.98.1 test --release --test build`. Expected:
  - `dilithium`: every phase-1 test passes, now over three backends, plus `soft_ring_and_host_modq_agree_op_by_op`; the guest makes 18 `MODQ` calls.
  - `msauth`: all pass.
  - `rand-guest build`: the committed `.bin`s reproduce.

- [ ] **Step 5: Commit**

```bash
git add guests-compiled/dilithium-core guest-sdk/src/lib.rs research/src/dilithium_host.rs guests-compiled/dilithium-verify/src guests-compiled/msauth/src guests-compiled/bin/dilithium-verify.bin* guests-compiled/bin/msauth.bin* research/tests/dilithium.rs
git commit -m "dilithium-core: Ring trait (SoftRing, HostModq, SyscallRing) over a 21-poly arena; canonical w1 equals the reference's caddq(w1); guests make 18 MODQ calls per verification"
```

### Task 7: Software trims — word input, word-state SHAKE, word ExpandA, no zero-fill, fused unpack, `use_hint`/`w1_pack`

**Files:**
- Modify: `guests-compiled/dilithium-core/src/{lib.rs,fips202.rs,poly.rs,packing.rs,verify.rs}`
- Modify: `guest-sdk/src/lib.rs` (`SyscallKeccak::permute_words`)
- Modify: `guests-compiled/dilithium-verify/src/main.rs`, `guests-compiled/msauth/src/main.rs`
  - Read `pk`/`sig` once as words into static buffers.
  - `msauth` hashes the same `pk` words for `MS_LEAF`.
- Rebuild: both `.bin`s
- Test: `research/tests/dilithium.rs`

**Interfaces:**
- Consumes: Task 6.
- Produces:
  ```rust
  pub trait Keccak { fn permute(&mut self, s: &mut [u64; 25]); fn permute_words(&mut self, w: &mut [u32; 50]) { /* default: join, permute, split */ } }
  pub fn uniform_words<K: Keccak>(k: &mut K, out: &mut [u32; 256], rho: &[u8; 32], nonce: u16);           // poly.rs
  pub fn unpack_t1_shifted(out: &mut [[u32; 256]; 4], pk: &[u8; 1312]);                                    // packing.rs
  pub fn unpack_z_checked(out: &mut [[u32; 256]; 4], sig: &[u8; 2420]) -> bool;                            // false iff ‖z‖∞ ≥ γ1 − β
  pub fn verify_words_with<K: Keccak, R: Ring>(k: &mut K, r: &mut R, ar: &mut Arena, pk: &[u32; 328], m: &[u8], sig: &[u32; 605]) -> bool;
  pub fn use_hint_pack_w1(out: &mut [u8; 768], w: &[[u32; 256]; 4], h: &[[u32; 256]; 4]);                      // rounding.rs: use_hint then w1_pack in one pass over the canonical w (ruling 4)
  ```
  - `uniform_words` equals `poly::uniform` coefficient for coefficient.
  - `verify_words_with` views the words as little-endian bytes. Add `#[cfg(not(target_endian = "little"))] compile_error!`.

- [ ] **Step 1: Write the failing tests** (append to `research/tests/dilithium.rs`)

```rust
#[test]
fn uniform_words_matches_the_reference_uniform() {
    use dilithium_core::poly::{uniform, uniform_words, Poly};
    for s in 0..200u16 {
        let rho: [u8; 32] = core::array::from_fn(|i| (i as u16 * 37 + s * 11) as u8);
        let mut want = Poly::default();
        uniform(&mut HostKeccak, &mut want, &rho, s);
        let mut got = [0u32; 256];
        uniform_words(&mut HostKeccak, &mut got, &rho, s);
        assert_eq!(got, core::array::from_fn(|i| want.coeffs[i] as u32), "nonce {s}");
    }
}

#[test]
fn permute_words_is_permute_in_the_syscall_layout() {
    use dilithium_core::Keccak;
    let mut s: [u64; 25] = core::array::from_fn(|i| 0x0123_4567_89ab_cdefu64.rotate_left(i as u32 * 7));
    let mut w = rand_zkvm::keccak::state_to_words(&s);
    HostKeccak.permute(&mut s);
    HostKeccak.permute_words(&mut w);
    assert_eq!(w, rand_zkvm::keccak::state_to_words(&s));
}

#[test]
fn fused_unpack_matches_the_reference_unpack_and_chknorm() {
    use dilithium_core::{packing, params, poly};
    for seed in 0..60u64 {
        let (kp, msg) = case(400 + seed, 33);
        let mut sig = kp.sign(&msg).to_vec();
        if seed % 3 == 0 { sig[32 + (seed as usize * 13) % 2304] ^= 0x40; }
        let pk: [u8; 1312] = kp.public.to_bytes().try_into().unwrap();
        let sig: [u8; 2420] = sig.try_into().unwrap();
        let (mut rho, mut t1) = ([0u8; 32], poly::Polyveck::default());
        packing::unpack_pk(&mut rho, &mut t1, &pk);
        let mut t1s = [[0u32; 256]; 4];
        packing::unpack_t1_shifted(&mut t1s, &pk);
        for k in 0..4 { for i in 0..256 { assert_eq!(t1s[k][i], (t1.vec[k].coeffs[i] << 13) as u32); } }
        let (mut c, mut z, mut h) = ([0u8; 32], poly::Polyvecl::default(), poly::Polyveck::default());
        let ok = packing::unpack_sig(&mut c, &mut z, &mut h, &sig);
        let mut zc = [[0u32; 256]; 4];
        let fused = packing::unpack_z_checked(&mut zc, &sig);
        assert_eq!(fused, poly::l_chknorm(&z, (params::GAMMA1 - params::BETA) as i32) == 0, "seed {seed}");
        if ok { for k in 0..4 { for i in 0..256 { assert_eq!(zc[k][i] as i64, (z.vec[k].coeffs[i] as i64).rem_euclid(rand_zkvm::modq::Q as i64)); } } }
    }
}
```

and extend `ours` with a fourth backend:

```rust
    let wpk: [u32; 328] = core::array::from_fn(|i| u32::from_le_bytes(pk[4 * i..4 * i + 4].try_into().unwrap()));
    let wsig: [u32; 605] = core::array::from_fn(|i| u32::from_le_bytes(sig[4 * i..4 * i + 4].try_into().unwrap()));
    assert_eq!(dilithium_core::verify_words_with(&mut HostKeccak, &mut HostModq, &mut Box::new(Arena::new()), &wpk, msg, &wsig), reference, "word path");
```

and (pre-flight ruling 4):

```rust
fn reference_w1(w: &[[u32; 256]; 4], h: &[[u32; 256]; 4]) -> [u8; 768] {
    use dilithium_core::poly;
    let (mut rw, mut rh) = (poly::Polyveck::default(), poly::Polyveck::default());
    for k in 0..4 { for i in 0..256 { rw.vec[k].coeffs[i] = w[k][i] as i32; rh.vec[k].coeffs[i] = h[k][i] as i32; } }
    poly::k_use_hint(&mut rw, &rh);
    let mut out = [0u8; 768];
    poly::k_pack_w1(&mut out, &rw);
    out
}

#[test]
fn use_hint_pack_w1_matches_the_reference_on_random_values_and_every_decompose_edge() {
    use dilithium_core::rounding::use_hint_pack_w1;
    let q = rand_zkvm::modq::Q;
    let mut s = 3u64;
    let mut next = move || { s ^= s << 13; s ^= s >> 7; s ^= s << 17; s };
    for round in 0..40 {
        let w: [[u32; 256]; 4] = core::array::from_fn(|_| core::array::from_fn(|_| (next() % q as u64) as u32));
        let h: [[u32; 256]; 4] = core::array::from_fn(|_| core::array::from_fn(|_| (next() % 7 == 0) as u32));
        let mut got = [0u8; 768];
        use_hint_pack_w1(&mut got, &w, &h);
        assert_eq!(got, reference_w1(&w, &h), "round {round}");
    }
    let g2 = 2 * dilithium_core::params::GAMMA2 as u32;
    let edges: Vec<u32> = (0..=44u32).flat_map(|m| [m * g2, (m * g2).saturating_sub(1), m * g2 + 1]).filter(|&x| x < q).chain([0, q - 1]).collect();
    for hint in [0u32, 1] {
        let w: [[u32; 256]; 4] = core::array::from_fn(|k| core::array::from_fn(|i| edges[(k * 256 + i) % edges.len()]));
        let mut got = [0u8; 768];
        use_hint_pack_w1(&mut got, &w, &[[hint; 256]; 4]);
        assert_eq!(got, reference_w1(&w, &[[hint; 256]; 4]), "decompose edges, hint {hint}");
    }
}
```

- [ ] **Step 2: Run to verify it fails.** `cd research && cargo +1.98.1 test --release --test dilithium`. Expected: compile error, no `uniform_words`, `permute_words`, `unpack_t1_shifted`, `unpack_z_checked`, `verify_words_with` or `use_hint_pack_w1`.

- [ ] **Step 3: Implement** spec §4.2's rows.
  - `Shake` keeps its state as `[u32; 50]` and calls `permute_words`. `SyscallKeccak` overrides `permute_words` with the bare `keccak(&mut w)` syscall.
  - `uniform_words` takes four candidates per three state words straight from the rate (42 words per block):
    ```
    c0 = w0 & M
    c1 = (w0 >> 24 | w1 << 8) & M
    c2 = (w1 >> 16 | w2 << 16) & M
    c3 = (w2 >> 8) & M          with M = 0x7f_ffff
    ```
    Accept `< q` and stop at 256. Follow the reference's 5-block first squeeze, then one block at a time.
  - `unpack_z_checked`:
    - Compute the centred `z = γ1 − t` and the bound check before canonicalising.
    - Return `false` on any `|z| ≥ γ1 − β`. That keeps the reference's semantics: `verify_words_with` then returns `false` exactly where the reference does.
    - Keep `unpack_sig`'s hint checks verbatim and in the same order.
  - `use_hint_pack_w1`: one pass over the canonical `w`.
    - `decompose`'s `a1` comes from the reference formula `(((a + 127) >> 7)·11275 + 2^23) >> 24`, with the fold to 0 at 44.
    - The hint's direction comes from `a0 > 0` with the reference's centred `a0`, computed once per coefficient.
    - The ±1 mod 44 is a compare chain, not a `%`.
    - Four 6-bit `w1` values go into 3 bytes, written as whole words.
    - `verify_words_with` calls it in place of `k_use_hint` plus `k_pack_w1`. The target is ≈ 12 k cycles per verification for both together (spec §4.2).
  - Guests: read `pk`/`sig` words with one `read_input` each into `static mut` word buffers, and call `verify_words_with`.
  - Rebuild both guests:

```bash
cd rand-guest && cargo +1.98.1 run -- build ../guests-compiled/dilithium-verify --out ../guests-compiled/bin/dilithium-verify.bin --max-words 65535
cargo +1.98.1 run -- build ../guests-compiled/msauth --out ../guests-compiled/bin/msauth.bin --max-words 65535
```

- [ ] **Step 4: Run to verify it passes.** `cargo +1.98.1 test --release --test dilithium && cargo +1.98.1 test --release --test msauth && cd ../rand-guest && cargo +1.98.1 test --release --test build`. Expected: all pass, with four backends agreeing everywhere.

- [ ] **Step 5: Commit**

```bash
git add guests-compiled/dilithium-core guest-sdk/src/lib.rs guests-compiled/dilithium-verify/src guests-compiled/msauth/src guests-compiled/bin/dilithium-verify.bin* guests-compiled/bin/msauth.bin* research/tests/dilithium.rs
git commit -m "dilithium-core: trims — word-state SHAKE (permute_words), ExpandA from state words, fused t1/z unpack with chknorm on the centred z, one-pass use_hint + w1_pack, word input; four backends agree"
```

### Task 8: Re-measure, pin the shape, and decide `M_MAX` at tier 18

Ruling (pre-flight 4): **tier 18 only.** The tier comes from `Tier::for_workload(cycles, permutations)`, the prover's own test with the Poseidon2 permutations counted, not from cycles alone. If `M = 3` does not fit tier 18, `M_MAX = 2` and `UNIFORM` is recorded as phase 3b. Never tier 19 or 20.

**Files:**
- Modify: `research/src/msauth.rs`
  - `MSAUTH_TIER`, `pinned_options()`, `poseidon2_permutations()`
  - `M_MAX` (only if the gate fails)
- Modify: `guests-compiled/msauth/src/main.rs` (`const M_MAX`, only if the gate fails), and rebuild `guests-compiled/bin/msauth.bin*`
- Modify: `research/tests/dilithium.rs` (the per-verification ceiling)
- Modify: `research/tests/msauth.rs`: the gate measurement, `proof_shape_is_the_same_for_every_m`, and the ignored Production prove
- Modify: `research/docs/04-guests.md`; `docs/superpowers/specs/2026-10-11-rvm-modq-chip-design.md` §4.3

**Interfaces:**
- Consumes: Tasks 4 and 6–7; `Tier::for_workload`; `Program::digest_rows`; `hash::{input_digest_row_count, public_digest_row_count}`.
- Produces (`rand_zkvm::msauth`):
  ```rust
  pub const MSAUTH_TIER: Tier = Tier(18);
  pub fn poseidon2_permutations(program: &Program, n_inputs: usize, exec: &Execution) -> usize; // digests + POSEIDON2 absorb rows, as build_traces_inner counts them
  pub fn pinned_options() -> ProveOptions;  // min_{keccak,modq,mem}_log_height at their M_MAX values (recorded in Step 3), gas_limit None
  ```

- [ ] **Step 1: Write the failing tests.** In `research/tests/dilithium.rs`'s `the_guest_verifies_like_the_host_and_reports_its_cycles`, replace the tier-20 assertion with:

```rust
        assert!(exec.cycles() < 110_000, "one verification with the MODQ chip and trims: {} cycles (spec §4.2 expects ≈ 79 k)", exec.cycles());
```

Append to `research/tests/msauth.rs`:

```rust
// ---- MODQ phase 3, Task 8: the tier-18 gate and the pinned shape ----------------------------

fn full_run(k: usize) -> (rand_zkvm::isa::Program, Vec<u32>, rand_zkvm::emulator::Execution) {
    let f = fixture(M_MAX);
    let slots: Vec<Slot> = (0..k).map(|i| slot(&f, i, &BINDING)).collect();
    let input = msauth_inputs(&MSK, &SALT, 1, &slots);
    let e = exec(&input, &BINDING);
    (compiled::msauth(), input, e)
}

#[test]
fn m_max_fits_tier_18_counting_cycles_and_poseidon2_permutations() {
    let (p, input, e) = full_run(M_MAX);
    let cycles = e.cycles() + p.digest_rows() + rand_zkvm::hash::input_digest_row_count(input.len()) + rand_zkvm::hash::public_digest_row_count(8);
    let perms = poseidon2_permutations(&p, input.len(), &e);
    let tier = Tier::for_workload(cycles, perms);
    eprintln!("GATE: M_MAX = {M_MAX}: {cycles} cycles, {perms} Poseidon2 permutations -> {tier:?}");
    assert_eq!(tier, Some(MSAUTH_TIER), "ruling: M_MAX must fit tier 18 — if this fails at M_MAX = 3, set M_MAX = 2 (Task 8 Step 3)");
}

#[test]
fn proof_shape_is_the_same_for_every_m() {
    let mut shapes = Vec::new();
    for k in 1..=M_MAX {
        let (p, input, e) = full_run(k);
        let t = rand_zkvm::machine::build_traces_salted_with(&p, &input, &BINDING, [0; 4], &e, MSAUTH_TIER, pinned_options()).unwrap();
        shapes.push((t.program_log_height, t.input_log_height, t.keccak_log_height, t.sha256_log_height, t.modq_log_height, t.public_log_height, t.mem_log_height));
    }
    assert!(shapes.windows(2).all(|w| w[0] == w[1]), "every M declares M_MAX's shape: {shapes:?}");
}

#[test]
#[ignore = "MODQ Task 8: one Production proof at M_MAX, tier 18 — run under /usr/bin/time -l on the 48 GB laptop and record peak RSS, mem_log_height, proof bytes and prove time"]
fn msauth_proves_at_m_max_production() {
    use rand_zkvm::machine::{FriProfile, Machine};
    let (p, input, _) = full_run(M_MAX);
    let m = Machine::new(FriProfile::Production);
    let t0 = std::time::Instant::now();
    let (proof, _) = m.prove_with_options(&p, &input, &BINDING, Some(MSAUTH_TIER), pinned_options()).unwrap();
    let prove = t0.elapsed();
    m.verify_public(&p.digest(), &BINDING, &proof).unwrap();
    eprintln!("msauth M_MAX = {M_MAX} Production: tier {:?}, mem_log_height {}, keccak {}, modq {}, proof {} B, prove {prove:?}",
              proof.tier, proof.mem_log_height, proof.keccak_log_height, proof.modq_log_height, proof.size());
}
```

- [ ] **Step 2: Run to verify it fails.** `cd research && cargo +1.98.1 test --release --test msauth m_max_fits proof_shape -- --nocapture`. Expected: compile error, no `MSAUTH_TIER`, `poseidon2_permutations` or `pinned_options`.

- [ ] **Step 3: Implement and decide.**
  1. Add `MSAUTH_TIER`, and `poseidon2_permutations`, which sums `program.digest_rows() + input_digest_row_count + public_digest_row_count(8)` and the `HashRow::Absorb` events, exactly as `build_traces_inner`'s `permutations`. Give `pinned_options()` placeholder-free floors: the `keccak_log_height`, `modq_log_height` and `mem_log_height` that `build_traces_salted_with(…, MSAUTH_TIER, ProveOptions::default())` declares for a full `M_MAX` run. Read them off a one-time `eprintln!` of that run, then write them in as literals with a comment naming the run.
  2. Run `cargo +1.98.1 test --release --test msauth m_max_fits proof_shape -- --nocapture`, and record the `GATE:` line verbatim.
  3. **If it is green at `M_MAX = 3`:** the gate is met.
  4. **If `m_max_fits…` fails at `M_MAX = 3`:**
     - Set `M_MAX = 2` in `research/src/msauth.rs` and in `guests-compiled/msauth/src/main.rs` (`MSAUTH_WORDS` follows).
     - Rebuild the guest:
       ```bash
       cd rand-guest && cargo +1.98.1 run -- build ../guests-compiled/msauth --out ../guests-compiled/bin/msauth.bin --max-words 65535
       ```
     - Re-derive the `pinned_options()` literals.
     - Re-run the **whole** `msauth` suite: `cargo +1.98.1 test --release --test msauth`. Any test written for three slots that now fails is adjusted to `M_MAX`; never delete it.
  5. Run the Production proof on the laptop and record its numbers:
     ```bash
     /usr/bin/time -l cargo +1.98.1 test --release --test msauth msauth_proves_at_m_max_production -- --ignored --nocapture 2>&1 | tee /tmp/msauth-prod.log
     ```
     Record the `maximum resident set size`, `mem_log_height`, proof bytes and prove time from the log.
  6. **Records.**
     - `04-guests.md`: replace the `dilithium-verify` table with the new cycles, `MODQ` calls (18), `KECCAK` calls, program words and `hc`, keeping the phase-1 row as history. Add the `msauth` table: `M = 1..M_MAX` cycles, Poseidon2 permutations, tier, the pinned heights, and the Production prove's peak RSS, `mem_log_height`, bytes and time.
     - Spec §4.3: the measured values beside the estimates, and the outcome in one sentence: either "`M_MAX = 3` at tier 18", or "`M_MAX = 2` at tier 18; `UNIFORM` is phase 3b".

- [ ] **Step 4: Run** `cargo +1.98.1 test --release --test dilithium --test msauth && cd ../rand-guest && cargo +1.98.1 test --release --test build`. Expected: all pass, and the committed `.bin`s reproduce.

- [ ] **Step 5: Commit** (the message names the measured values; write them in from Step 3's output)

```bash
git add research/src/msauth.rs research/tests/dilithium.rs research/tests/msauth.rs research/docs/04-guests.md docs/superpowers/specs/2026-10-11-rvm-modq-chip-design.md guests-compiled/msauth/src guests-compiled/bin/msauth.bin*
git commit -m "msauth: the tier-18 gate measured with MODQ — per verification, M_MAX, cycles, Poseidon2 permutations and the Production prove's peak RSS in docs/04-guests.md; shape pinned for every M"
```

### Task 9: Docs, fork notes and the recursion re-pin

**Files:**
- Modify: `research/docs/01-isa.md` (syscall table: row 8 `MODQ base a1`, gas 168)
- Modify: `research/docs/02-tables-and-buses.md`
  - A `## modq — main, col::WIDTH = 59 + preprocessed, pre::WIDTH = 16` section, after `sha256`'s.
  - A `### MODQ: the SYS_MODQ ecall row` subsection, after `SHA256`'s.
  - The `cpu` width becomes 283.
  - `MODQ` and `MODQ_WIRE` go in the bus catalogue.
  - The degree budget gains the modq row.
- Modify: `research/docs/05-roadmap.md` (a "Constraint set: the MODQ chip" section: what moved, the measured proof-size deltas, "every verifier key changed; ships only with a chain cut", and the sync-zkvm steps of spec §6)
- Modify: `docs/superpowers/specs/2026-10-11-private-multisig-design.md` §7 (phase 3 row: syscall 8, link to this spec)
- Modify, **only after rVM phase 4 has been merged into this branch** (`git merge`, never rebase; Step 6):
  - `recursion/src/programs/verify_rv32.digest`
  - `recursion/tests/pins.json`
  - the literals in `recursion/tests/{exit,aggregate,self_verify,verifier_key,memprofile}.rs` that move

**Interfaces:**
- Consumes: Tasks 4 and 8's numbers. `research/tests/e2e.rs`'s production-profile measurement test supplies the proof-size deltas.
- Produces: docs only, plus recursion pins re-recorded from measured runs.

- [ ] **Step 1: Write the failing check** (append to `research/tests/modq.rs`)

```rust
/// Reads the docs at run time, not with `include_str!`: `deploy/sync-zkvm.sh` vendors this file into
/// the fullnode, where `docs/` does not exist, and the check is skipped there.
#[test]
fn the_docs_name_the_chip_where_the_isa_and_tables_are_documented() {
    let doc = |f: &str| std::fs::read_to_string(format!("{}/docs/{f}", env!("CARGO_MANIFEST_DIR")));
    let (Ok(isa), Ok(tables)) = (doc("01-isa.md"), doc("02-tables-and-buses.md")) else {
        eprintln!("docs/ not present (a vendored copy): skipped");
        return;
    };
    assert!(isa.contains("| 8 | `MODQ base a1`"), "01-isa.md syscall table row 8");
    assert!(tables.contains("## `modq` — main, `col::WIDTH = 59`"), "02-tables-and-buses.md modq section");
    assert!(tables.contains("`MODQ_WIRE`"), "the bus catalogue");
    assert_eq!(rand_zkvm::tables::modq::col::WIDTH, 59);
    assert_eq!(rand_zkvm::tables::cpu::col::WIDTH, 283);
}
```

- [ ] **Step 2: Run to verify it fails.** `cd research && cargo +1.98.1 test --release --test modq the_docs`. Expected: fails on the `01-isa.md` assertion.

- [ ] **Step 3: Implement the docs.**
  - Write each section from spec §3, in the house style of the `sha256` sections they sit beside.
  - Measure the production proof-size deltas with `cargo +1.98.1 test --release --test e2e measure_production_profile -- --ignored --nocapture`, run twice, once on `main` and once on this branch. Record:
    - the chip-free tier-10 delta;
    - a one-modq-block tier-10 delta.
  - Write the fullnode re-vendor list from spec §6, including `NO_MODQ` beside `NO_KECCAK`/`NO_SHA256` in `executor.rs`, that `pad_absent_hash_tables` does not pad modq, and the client `TIERS` users.

- [ ] **Step 4: Run** `cargo +1.98.1 test --release --test modq`. Expected: all pass.

- [ ] **Step 5: Commit the docs**

```bash
git add research/docs docs/superpowers/specs research/tests/modq.rs
git commit -m "docs: the MODQ chip — ISA row 8, the modq table and SYS_MODQ row, buses, constraint-set notes with measured proof-size deltas, fullnode re-vendor steps"
```

- [ ] **Step 6: The recursion re-pin, after phase 4 lands.**
  1. **Merge, never rebase.** This branch carries merge `26f547e` (circuits `feat/scan-compact` `56b7061`, the fullnode `CIRCUITS_PIN` base). A rebase would drop it.
     - `git fetch origin`.
     - Check whether phase 4 is on `origin/main` (`git merge-base --is-ancestor origin/feat/rvm-phase4-spans origin/main`). Circuits `main` may lag it, and `CIRCUITS_PIN` lives in the fullnode, not here.
     - If it is, `git merge --no-ff origin/main`. If not, `git merge --no-ff origin/feat/rvm-phase4-spans` once that branch's re-pin commit exists.
     - Afterwards check `git merge-base --is-ancestor 26f547e HEAD`.
     - Resolve conflicts only in this branch's own files. **Stop and report** if a conflict lands in `recursion/`.
  2. **Which pins can be re-recorded here, on the 48 GB laptop:**
     - every non-ignored test, via `cd recursion && cargo +1.98.1 test --release 2>&1 | tail -40`;
     - `recursion/tests/profile.rs:103` `where_the_rows_go`, via `cargo +1.98.1 test --release --test profile where_the_rows_go -- --ignored --nocapture` (one ≈ 100 s Production proof).
  3. **Which pins stay stale until a 256 GB machine exists:**
     - `recursion/tests/tree_measure.rs:117` `production_leaf_l2`;
     - `recursion/tests/tree_measure.rs:154` `production_rv32r_over_the_leaf_proves`.
     
     Do not run them here, and do not edit their `#[ignore]` text or pins. List both as stale in the commit body and in `research/docs/05-roadmap.md`'s MODQ section.
  4. Classify each failure. It must be a pin that moved because the inner cpu table gained `SYS_MODQ`: `verify_rv32.digest`, `pins.json`, `inner_vk_digest`, row literals, or verifier-key caps. Anything else (a refused honest proof, a panic) is a defect: stop and report BLOCKED with the output.
  5. **If any recursion tier moves** (any tier literal or assertion, or a `pins.json` tier field), **stop and report**, and re-record nothing. One cpu column should move rows, not tiers.
  6. Re-record each remaining pin from its failure's `left`/`right`, and extend its history comment with `MODQ chip (2026-10-11, private multisig phase 3): the inner cpu gained SYS_MODQ: <old> → <new>.`.
  7. Re-run until green.

- [ ] **Step 7: Commit the re-pin**

```bash
git add recursion/src/programs/verify_rv32.digest recursion/tests
git commit -m "recursion: re-pin for the MODQ chip — the inner rVM's cpu gained SYS_MODQ (283 columns); program digests, pins.json, inner_vk_digest and row/tier literals re-recorded from measured runs; stale until a 256 GB machine: tree_measure.rs production_leaf_l2 and production_rv32r_over_the_leaf_proves"
```

Merging, pushing, the fullnode re-vendor and the chain cut are the operator's calls.
