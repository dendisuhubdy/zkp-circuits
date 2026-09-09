# CUDA Prover Backend Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Move the LDE NTTs and Poseidon2 Merkle commitments of the Rand zkVM prover onto an NVIDIA GPU behind a `--cuda` flag, producing proofs the unchanged CPU verifier accepts.

**Architecture:** A stable crate `rand-zkvm-cuda` implements Plonky3's `TwoAdicSubgroupDft` and `Mmcs` traits generically over two small "engine" traits (NTT primitives, hashing primitives). A pure-Rust `CpuNttEngine`/`CpuHashEngine` and a `CudaNttEngine`/`CudaHashEngine` share the same per-thread kernel bodies (`src/device/`), so the GPU orchestration is exercised on the CPU by a mock driver that runs those bodies sequentially. The cuda-oxide crate `gpu-kernels` only wraps the shared bodies in `#[kernel]` entry points; its PTX is committed and loaded at runtime by `cuda-core`.

**Tech Stack:** Rust 1.98.1 (stable) for everything except `gpu-kernels` (cuda-oxide, nightly-2026-08-28). Plonky3 `=0.7.0`, `cuda-core =0.3.1` (optional), `rand 0.10`, `postcard 1`, `thiserror 2`.

**Spec:** `circuits/docs/superpowers/specs/2026-09-10-cuda-prover-design.md`

## Global Constraints

- Every Plonky3 crate pinned `=0.7.0`; `rand = "0.10"` (distribution type is `rand::distr::StandardUniform`).
- `rand-zkvm-cuda` must build on stable 1.98.1 with **no** CUDA toolkit present (default features). `cuda-core` is behind feature `cuda` only.
- Goldilocks `p = 0xFFFF_FFFF_0000_0001`; every value handed to Plonky3 is canonical (`< p`).
- Poseidon2: width 8, S-box x^7, 4 initial + 4 terminal external rounds, 22 internal rounds, external MDS `[2 3 1 1;1 2 3 1;1 1 2 3;3 1 1 2]` per 4-chunk plus circulant sums, internal diagonal `MATRIX_DIAG_8_GOLDILOCKS = [-2, 1, 2, 1/2, 3, -1/2, -3, -4]`; the initial external phase applies the MDS light permutation **before** its first round.
- Sponge: `PaddingFreeSponge<Perm, 8, 4, 4>`; compress: `TruncatedPermutation<Perm, 2, 4, 8>`; Merkle arity `N = 2`, `DIGEST_ELEMS = 4`, `SALT_ELEMS = 4`, cap height 2.
- The GPU/reference tree must reproduce Plonky3's `MerkleTreeHidingMmcs` caps and openings bit for bit; Plonky3's own `verify_batch`/`verify_multi_batch` are the oracle.
- `Machine::verify` and `verifier_key` never touch the new crate.
- No silent CPU fallback anywhere in the `--cuda` path.
- Commit after every task; never leave the crate failing `cargo test`.
- Another Claude session edits `circuits/research/src/{viewing,notes,ledger,arx}.rs` and `docs/06`. Do not touch those files. Only `machine.rs`, `lib.rs`, `Cargo.toml`, `main.rs` (feature wiring) and new test files change in `research`.

---

## File structure

```
circuits/
  rand-zkvm-cuda/
    Cargo.toml
    src/lib.rs                     re-exports; feature gates
    src/device/mod.rs              `pub mod gl; pub mod poseidon2; pub mod kernels;` (no deps, no_std-clean)
    src/device/gl.rs               Goldilocks u64 arithmetic                       (Task 1)
    src/device/poseidon2.rs        permutation, hash_row, compress over u64         (Task 2)
    src/device/kernels.rs          per-thread kernel bodies                         (Task 3, 5)
    src/constants.rs               host regeneration of Poseidon2 round constants   (Task 2)
    src/ntt/mod.rs                 Twiddles, LOG_MAX, NttEngine trait               (Task 3)
    src/ntt/cpu.rs                 CpuNttEngine                                     (Task 3)
    src/dft.rs                     Dft<E>: TwoAdicSubgroupDft<Goldilocks>           (Task 4)
    src/merkle/mod.rs              HashEngine trait, Tree, Layer plan               (Task 5)
    src/merkle/cpu.rs              CpuHashEngine                                    (Task 5)
    src/merkle/prune.rs            pruned multi-proof (mirror of Plonky3 pruning)   (Task 6)
    src/merkle/mmcs.rs             HidingMmcs<E>: Mmcs<Goldilocks>                  (Task 6)
    src/gpu/mod.rs                 CudaError, GpuProver                             (Task 8)
    src/gpu/driver/mod.rs          Device/Module/Function/Buffer/Arg surface        (Task 8)
    src/gpu/driver/real.rs         cuda-core implementation        [feature cuda]  (Task 8)
    src/gpu/driver/mock.rs         CPU emulation via device::kernels [feature mock-driver] (Task 8)
    src/gpu/ntt.rs                 CudaNttEngine                                    (Task 9)
    src/gpu/hash.rs                CudaHashEngine                                   (Task 9)
    ptx/PTX_BUILD.md               how kernels.sm_80.ptx was produced               (Task 7)
    tests/*.rs                     equality tests against Plonky3
  gpu-kernels/
    Cargo.toml, rust-toolchain.toml, src/main.rs, Justfile                          (Task 7)
  research/  (feature wiring only)
    Cargo.toml, src/machine.rs, src/lib.rs, tests/backend.rs                        (Task 10)
fullnode/
  crates/shrugg-zkvm/Cargo.toml, src/executor.rs, deploy/sync-zkvm.sh              (Task 11)
  crates/shrugg-client/Cargo.toml, src/main.rs, docs/confidential.md               (Task 11)
```

Column-major layout convention used by every NTT primitive: element `(row, col)` of an `n × w` matrix lives at `col * n + row`. Row-major (Plonky3) is `row * w + col`.

---

### Task 1: Crate scaffold and Goldilocks arithmetic

**Files:**
- Create: `circuits/rand-zkvm-cuda/Cargo.toml`
- Create: `circuits/rand-zkvm-cuda/src/lib.rs`
- Create: `circuits/rand-zkvm-cuda/src/device/mod.rs`
- Create: `circuits/rand-zkvm-cuda/src/device/gl.rs`
- Test: `circuits/rand-zkvm-cuda/tests/gl.rs`

**Interfaces:**
- Produces: `device::gl::{P, EPSILON, reduce, add, sub, neg, mul, reduce128, pow, inv}` all over `u64`, inputs and outputs canonical.

- [ ] **Step 1: Create the crate**

```toml
# circuits/rand-zkvm-cuda/Cargo.toml
[package]
name = "rand-zkvm-cuda"
version = "0.1.0"
edition = "2021"
description = "GPU (CUDA) NTT and Poseidon2 Merkle backends for the Rand zkVM, with CPU reference twins"

[lib]
name = "rand_zkvm_cuda"
path = "src/lib.rs"

[dependencies]
p3-field = "=0.7.0"
p3-dft = "=0.7.0"
p3-matrix = "=0.7.0"
p3-commit = "=0.7.0"
p3-merkle-tree = "=0.7.0"
p3-goldilocks = "=0.7.0"
p3-poseidon2 = "=0.7.0"
p3-symmetric = "=0.7.0"
p3-util = "=0.7.0"
rand = { version = "0.10", features = ["std_rng"] }
serde = { version = "1", features = ["derive"] }
thiserror = "2"
cuda-core = { version = "=0.3.1", optional = true }

[features]
default = []
cuda = ["dep:cuda-core"]
mock-driver = []
cuda-hw = ["cuda"]

[dev-dependencies]
p3-fri = "=0.7.0"
postcard = { version = "1", features = ["alloc"] }
```

```rust
// circuits/rand-zkvm-cuda/src/lib.rs
pub mod device;
```

```rust
// circuits/rand-zkvm-cuda/src/device/mod.rs
//! Code shared verbatim with the cuda-oxide kernel crate (`gpu-kernels` includes these
//! files by `#[path]`). No dependencies, no allocation, no std.
pub mod gl;
```

- [ ] **Step 2: Write the failing test**

```rust
// circuits/rand-zkvm-cuda/tests/gl.rs
use p3_field::{Field, PrimeCharacteristicRing, PrimeField64};
use p3_goldilocks::Goldilocks;
use rand::{Rng, SeedableRng, rngs::StdRng};
use rand_zkvm_cuda::device::gl;

fn g(x: u64) -> Goldilocks { Goldilocks::from_u64(x) }
fn c(x: Goldilocks) -> u64 { x.as_canonical_u64() }

const EDGE: [u64; 8] = [0, 1, 2, gl::P - 1, gl::P - 2, 1 << 32, (1 << 32) - 1, 0x7fff_ffff_8000_0001];

#[test]
fn add_sub_mul_match_plonky3() {
    let mut rng = StdRng::seed_from_u64(1);
    let mut cases: Vec<(u64, u64)> = EDGE.iter().flat_map(|&a| EDGE.iter().map(move |&b| (a, b))).collect();
    for _ in 0..10_000 { cases.push((rng.random::<u64>() % gl::P, rng.random::<u64>() % gl::P)); }
    for (a, b) in cases {
        assert_eq!(gl::add(a, b), c(g(a) + g(b)), "add {a} {b}");
        assert_eq!(gl::sub(a, b), c(g(a) - g(b)), "sub {a} {b}");
        assert_eq!(gl::mul(a, b), c(g(a) * g(b)), "mul {a} {b}");
        assert_eq!(gl::neg(a), c(-g(a)), "neg {a}");
    }
}

#[test]
fn reduce128_handles_full_range() {
    for x in [0u128, 1, (gl::P as u128) * (gl::P as u128) - 1, u128::MAX >> 1, (1u128 << 96) + 5, (1u128 << 64) - 1] {
        assert_eq!(gl::reduce128(x), (x % gl::P as u128) as u64);
    }
}

#[test]
fn pow_and_inv() {
    let mut rng = StdRng::seed_from_u64(2);
    for _ in 0..1000 {
        let a = rng.random::<u64>() % gl::P;
        let e = rng.random::<u64>();
        assert_eq!(gl::pow(a, e), c(g(a).exp_u64(e)));
        if a != 0 { assert_eq!(gl::inv(a), c(g(a).inverse())); }
    }
    assert_eq!(gl::pow(7, 0), 1);
}

#[test]
fn outputs_are_canonical() {
    assert!(gl::add(gl::P - 1, gl::P - 1) < gl::P);
    assert!(gl::mul(gl::P - 1, gl::P - 1) < gl::P);
    assert_eq!(gl::reduce(gl::P), 0);
}
```

- [ ] **Step 3: Run test to verify it fails**

Run: `cd circuits/rand-zkvm-cuda && cargo test --test gl`
Expected: compile error, `gl` has no items.

- [ ] **Step 4: Implement `gl.rs`**

```rust
// circuits/rand-zkvm-cuda/src/device/gl.rs
//! Goldilocks field, p = 2^64 - 2^32 + 1, over plain `u64`. Every function takes and
//! returns canonical values (`< P`). Written so the same source compiles to PTX.
pub const P: u64 = 0xFFFF_FFFF_0000_0001;
/// 2^64 mod p = 2^32 - 1.
pub const EPSILON: u64 = 0xFFFF_FFFF;

#[inline(always)]
pub fn reduce(x: u64) -> u64 { if x >= P { x - P } else { x } }

#[inline(always)]
pub fn add(a: u64, b: u64) -> u64 {
    let (s, carry) = a.overflowing_add(b);
    // carry means the true sum is s + 2^64 ≡ s + EPSILON; that add cannot overflow again
    // because s < 2p - 2^64 = 2^64 - 2^33 + 2.
    let s = if carry { s.wrapping_add(EPSILON) } else { s };
    reduce(s)
}

#[inline(always)]
pub fn sub(a: u64, b: u64) -> u64 {
    let (d, borrow) = a.overflowing_sub(b);
    // borrow means the true value is d - 2^64 ≡ d - EPSILON; d ≥ 2^32 so no underflow.
    if borrow { d.wrapping_sub(EPSILON) } else { d }
}

#[inline(always)]
pub fn neg(a: u64) -> u64 { if a == 0 { 0 } else { P - a } }

/// Reduce a 128-bit product. With x = lo + hi_lo·2^64 + hi_hi·2^96 and 2^64 ≡ EPSILON,
/// 2^96 ≡ -1: x ≡ lo - hi_hi + hi_lo·EPSILON.
#[inline(always)]
pub fn reduce128(x: u128) -> u64 {
    let lo = x as u64;
    let hi = (x >> 64) as u64;
    let hi_hi = hi >> 32;
    let hi_lo = hi & EPSILON;
    let (t0, borrow) = lo.overflowing_sub(hi_hi);
    let t0 = if borrow { t0.wrapping_sub(EPSILON) } else { t0 };
    let t1 = hi_lo * EPSILON; // < 2^64
    let (r, carry) = t0.overflowing_add(t1);
    let r = if carry { r.wrapping_add(EPSILON) } else { r };
    reduce(r)
}

#[inline(always)]
pub fn mul(a: u64, b: u64) -> u64 { reduce128((a as u128) * (b as u128)) }

pub fn pow(mut base: u64, mut e: u64) -> u64 {
    let mut acc = 1u64;
    while e != 0 {
        if e & 1 == 1 { acc = mul(acc, base); }
        base = mul(base, base);
        e >>= 1;
    }
    acc
}

/// Fermat inverse; host-side use only (~64 squarings).
pub fn inv(a: u64) -> u64 { pow(a, P - 2) }
```

- [ ] **Step 5: Run tests, expect pass**

Run: `cargo test --test gl` → all 4 pass.

- [ ] **Step 6: Commit**

```bash
cd circuits && git add rand-zkvm-cuda && git commit -m "cuda: rand-zkvm-cuda crate scaffold and Goldilocks u64 arithmetic"
```

---

### Task 2: Poseidon2 over u64 and host constant regeneration

**Files:**
- Create: `src/device/poseidon2.rs`
- Create: `src/constants.rs`
- Modify: `src/device/mod.rs` (add `pub mod poseidon2;`), `src/lib.rs` (add `pub mod constants;`)
- Test: `tests/poseidon2.rs`

**Interfaces:**
- Consumes: `device::gl`.
- Produces: `device::poseidon2::{N_CONSTS = 86, permute(&mut [u64; 8], k: &[u64]), hash_row(row: &[u64], k: &[u64]) -> [u64; 4], compress(a: &[u64; 4], b: &[u64; 4], k: &[u64]) -> [u64; 4]}`; `constants::{poseidon2_constants(seed: u64) -> [u64; 86], permutation(seed) -> Poseidon2Goldilocks<8>}`. Layout of `k`: `[0..32)` initial rounds (4 × 8), `[32..54)` internal (22), `[54..86)` terminal (4 × 8).

- [ ] **Step 1: Write the failing test**

```rust
// circuits/rand-zkvm-cuda/tests/poseidon2.rs
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_goldilocks::{Goldilocks, Poseidon2Goldilocks};
use p3_symmetric::{CryptographicHasher, PaddingFreeSponge, Permutation, PseudoCompressionFunction, TruncatedPermutation};
use rand::{Rng, SeedableRng, rngs::StdRng};
use rand_zkvm_cuda::constants::{permutation, poseidon2_constants};
use rand_zkvm_cuda::device::poseidon2;

const SEED: u64 = 0x5261_6e64_5a4b; // the zkVM's PERM_SEED ("RandZK")

fn to_u64(v: &[Goldilocks]) -> Vec<u64> { v.iter().map(|x| x.as_canonical_u64()).collect() }

#[test]
fn regenerated_permutation_matches_new_from_rng_128() {
    let ours = permutation(SEED);
    let theirs = Poseidon2Goldilocks::<8>::new_from_rng_128(&mut StdRng::seed_from_u64(SEED));
    let mut rng = StdRng::seed_from_u64(9);
    for _ in 0..100 {
        let s: [Goldilocks; 8] = core::array::from_fn(|_| Goldilocks::from_u64(rng.random::<u64>() % 0xFFFF_FFFF_0000_0001));
        assert_eq!(ours.permute(s), theirs.permute(s));
    }
}

#[test]
fn u64_permutation_matches_plonky3_for_many_seeds() {
    for seed in [SEED, 0, 1, 42, u64::MAX] {
        let perm = Poseidon2Goldilocks::<8>::new_from_rng_128(&mut StdRng::seed_from_u64(seed));
        let k = poseidon2_constants(seed);
        let mut rng = StdRng::seed_from_u64(seed ^ 7);
        for _ in 0..2000 {
            let raw: [u64; 8] = core::array::from_fn(|_| rng.random::<u64>() % 0xFFFF_FFFF_0000_0001);
            let expected = to_u64(&perm.permute(raw.map(Goldilocks::from_u64)));
            let mut st = raw;
            poseidon2::permute(&mut st, &k);
            assert_eq!(st.to_vec(), expected, "seed {seed}");
        }
    }
}

#[test]
fn hash_row_matches_padding_free_sponge() {
    let perm = Poseidon2Goldilocks::<8>::new_from_rng_128(&mut StdRng::seed_from_u64(SEED));
    let sponge = PaddingFreeSponge::<_, 8, 4, 4>::new(perm.clone());
    let k = poseidon2_constants(SEED);
    let mut rng = StdRng::seed_from_u64(3);
    for len in [0usize, 1, 2, 3, 4, 5, 7, 8, 9, 15, 16, 17, 52, 56, 60, 100] {
        let row: Vec<u64> = (0..len).map(|_| rng.random::<u64>() % 0xFFFF_FFFF_0000_0001).collect();
        let expected = to_u64(&sponge.hash_iter(row.iter().map(|&x| Goldilocks::from_u64(x))));
        assert_eq!(poseidon2::hash_row(&row, &k).to_vec(), expected, "len {len}");
    }
}

#[test]
fn compress_matches_truncated_permutation() {
    let perm = Poseidon2Goldilocks::<8>::new_from_rng_128(&mut StdRng::seed_from_u64(SEED));
    let tp = TruncatedPermutation::<_, 2, 4, 8>::new(perm);
    let k = poseidon2_constants(SEED);
    let mut rng = StdRng::seed_from_u64(4);
    for _ in 0..1000 {
        let a: [u64; 4] = core::array::from_fn(|_| rng.random::<u64>() % 0xFFFF_FFFF_0000_0001);
        let b: [u64; 4] = core::array::from_fn(|_| rng.random::<u64>() % 0xFFFF_FFFF_0000_0001);
        let expected = to_u64(&tp.compress([a.map(Goldilocks::from_u64), b.map(Goldilocks::from_u64)]));
        assert_eq!(poseidon2::compress(&a, &b, &k).to_vec(), expected);
    }
}
```

- [ ] **Step 2: Run, expect compile failure** (`cargo test --test poseidon2`).

- [ ] **Step 3: Implement host constants**

```rust
// circuits/rand-zkvm-cuda/src/constants.rs
//! Regenerates the Poseidon2 round constants exactly as `Poseidon2Goldilocks::<8>::
//! new_from_rng_128(&mut StdRng::seed_from_u64(seed))` draws them: 4 initial rows, 4
//! terminal rows (via `ExternalLayerConstants::new_from_rng(8, rng)`), then 22 internal.
use p3_field::PrimeField64;
use p3_goldilocks::{Goldilocks, Poseidon2Goldilocks};
use p3_poseidon2::ExternalLayerConstants;
use rand::distr::{Distribution, StandardUniform};
use rand::{Rng, SeedableRng, rngs::StdRng};

pub const N_INITIAL: usize = 4;
pub const N_INTERNAL: usize = 22;
pub const N_TERMINAL: usize = 4;

pub fn permutation(seed: u64) -> Poseidon2Goldilocks<8> {
    Poseidon2Goldilocks::<8>::new_from_rng_128(&mut StdRng::seed_from_u64(seed))
}

pub fn poseidon2_constants(seed: u64) -> [u64; crate::device::poseidon2::N_CONSTS] {
    let mut rng = StdRng::seed_from_u64(seed);
    let ext = ExternalLayerConstants::<Goldilocks, 8>::new_from_rng(N_INITIAL + N_TERMINAL, &mut rng);
    let internal: Vec<Goldilocks> = (&mut rng).sample_iter(StandardUniform).take(N_INTERNAL).collect();
    let mut k = [0u64; crate::device::poseidon2::N_CONSTS];
    let mut i = 0;
    for row in ext.get_initial_constants() { for x in row { k[i] = x.as_canonical_u64(); i += 1; } }
    for x in &internal { k[i] = x.as_canonical_u64(); i += 1; }
    for row in ext.get_terminal_constants() { for x in row { k[i] = x.as_canonical_u64(); i += 1; } }
    debug_assert_eq!(i, crate::device::poseidon2::N_CONSTS);
    let _ = StandardUniform::sample(&StandardUniform, &mut rng); // keep the import used on all cfgs
    k
}
```
(If `Distribution::sample` on a unit struct fails to type-check, delete that last line; it is only there to avoid an unused-import warning.)

- [ ] **Step 4: Implement the device permutation**

```rust
// circuits/rand-zkvm-cuda/src/device/poseidon2.rs
//! Poseidon2, width 8, over Goldilocks u64. Mirrors p3-poseidon2 0.7 exactly:
//! initial MDS-light, 4 external rounds, 22 internal rounds, 4 external rounds.
use super::gl::{add, mul, sub};

pub const WIDTH: usize = 8;
pub const RATE: usize = 4;
pub const OUT: usize = 4;
pub const IDX_INITIAL: usize = 0;    // 4 rows × 8
pub const IDX_INTERNAL: usize = 32;  // 22 scalars
pub const IDX_TERMINAL: usize = 54;  // 4 rows × 8
pub const N_CONSTS: usize = 86;

#[inline(always)]
fn sbox(x: u64) -> u64 { let x2 = mul(x, x); let x4 = mul(x2, x2); mul(mul(x4, x2), x) }

#[inline(always)]
fn double(x: u64) -> u64 { add(x, x) }

/// [2 3 1 1; 1 2 3 1; 1 1 2 3; 3 1 1 2] · x, same operation order as p3 `apply_mat4`.
#[inline(always)]
fn mat4(x: &mut [u64], o: usize) {
    let t01 = add(x[o], x[o + 1]);
    let t23 = add(x[o + 2], x[o + 3]);
    let t0123 = add(t01, t23);
    let t01123 = add(t0123, x[o + 1]);
    let t01233 = add(t0123, x[o + 3]);
    x[o + 3] = add(t01233, double(x[o]));
    x[o + 1] = add(t01123, double(x[o + 2]));
    x[o] = add(t01123, t01);
    x[o + 2] = add(t01233, t23);
}

#[inline(always)]
fn mds_light(s: &mut [u64; WIDTH]) {
    mat4(s, 0);
    mat4(s, 4);
    let sums = [add(s[0], s[4]), add(s[1], s[5]), add(s[2], s[6]), add(s[3], s[7])];
    for i in 0..WIDTH { s[i] = add(s[i], sums[i % 4]); }
}

/// diag = [-2, 1, 2, 1/2, 3, -1/2, -3, -4]; state[i] = sum + diag[i]·state[i].
#[inline(always)]
fn internal_matmul(s: &mut [u64; WIDTH]) {
    let mut sum = 0u64;
    for i in 0..WIDTH { sum = add(sum, s[i]); }
    let half = |x: u64| -> u64 { if x & 1 == 0 { x >> 1 } else { (x >> 1) + 0x7FFF_FFFF_8000_0001 } }; // x/2 mod p
    s[0] = sub(sum, double(s[0]));
    s[1] = add(sum, s[1]);
    s[2] = add(sum, double(s[2]));
    s[3] = add(sum, half(s[3]));
    let three4 = add(double(s[4]), s[4]);
    s[4] = add(sum, three4);
    s[5] = sub(sum, half(s[5]));
    let three6 = add(double(s[6]), s[6]);
    s[6] = sub(sum, three6);
    let two7 = double(s[7]);
    s[7] = sub(sum, add(two7, two7));
}

pub fn permute(s: &mut [u64; WIDTH], k: &[u64]) {
    mds_light(s);
    for r in 0..4 {
        for i in 0..WIDTH { s[i] = sbox(add(s[i], k[IDX_INITIAL + r * WIDTH + i])); }
        mds_light(s);
    }
    for r in 0..22 {
        s[0] = sbox(add(s[0], k[IDX_INTERNAL + r]));
        internal_matmul(s);
    }
    for r in 0..4 {
        for i in 0..WIDTH { s[i] = sbox(add(s[i], k[IDX_TERMINAL + r * WIDTH + i])); }
        mds_light(s);
    }
}

/// `PaddingFreeSponge<_, 8, 4, 4>::hash_iter` over `row`.
pub fn hash_row(row: &[u64], k: &[u64]) -> [u64; OUT] {
    let mut s = [0u64; WIDTH];
    let mut i = 0;
    while i + RATE <= row.len() {
        s[0] = row[i]; s[1] = row[i + 1]; s[2] = row[i + 2]; s[3] = row[i + 3];
        permute(&mut s, k);
        i += RATE;
    }
    let rem = row.len() - i;
    if rem != 0 {
        for j in 0..rem { s[j] = row[i + j]; }
        permute(&mut s, k);
    }
    [s[0], s[1], s[2], s[3]]
}

/// `TruncatedPermutation<_, 2, 4, 8>::compress([a, b])`.
pub fn compress(a: &[u64; 4], b: &[u64; 4], k: &[u64]) -> [u64; 4] {
    let mut s = [a[0], a[1], a[2], a[3], b[0], b[1], b[2], b[3]];
    permute(&mut s, k);
    [s[0], s[1], s[2], s[3]]
}
```
Note on `half`: for odd x, x/2 mod p = (x + p)/2 = (x >> 1) + (p + 1)/2 = (x >> 1) + 0x7FFF_FFFF_8000_0001; the sum is < p because x < p.

- [ ] **Step 5: Run tests, expect pass** (`cargo test --test poseidon2`). If `u64_permutation_matches_plonky3_for_many_seeds` fails only, the bug is inside `permute`; compare a single round against `Poseidon2ExternalLayerGoldilocks` by temporarily printing states.

- [ ] **Step 6: Commit** — `git commit -m "cuda: Poseidon2 width-8 over u64 and host constant regeneration, equal to Plonky3"`.

---

### Task 3: NTT engine trait, kernel bodies, CPU engine

**Files:**
- Create: `src/device/kernels.rs`, `src/ntt/mod.rs`, `src/ntt/cpu.rs`
- Modify: `src/device/mod.rs`, `src/lib.rs`
- Test: `tests/ntt.rs`

**Interfaces:**
- Produces:
```rust
// src/ntt/mod.rs
pub const LOG_MAX: usize = 26;
pub const LO_BITS: usize = 13;
pub const LOG_TILE: usize = 10;              // shared-memory tile = 1024 elements
pub struct Twiddles { pub lo: Vec<u64>, pub hi: Vec<u64>, pub inv_lo: Vec<u64>, pub inv_hi: Vec<u64> }
pub fn twiddles() -> Twiddles;               // ω = Goldilocks::two_adic_generator(LOG_MAX)
pub trait NttEngine: Clone + Send + Sync + 'static {
    type Buf;
    fn max_columns(&self, n: usize) -> usize;                       // how many columns of height n fit at once
    fn upload_row_major(&self, values: &[u64], n: usize, w: usize) -> Self::Buf;   // → column-major on device
    fn download_row_major(&self, buf: &Self::Buf, n: usize, w: usize) -> Vec<u64>;
    fn dif(&self, buf: &mut Self::Buf, n: usize, w: usize, inverse: bool);         // natural in → bit-reversed out
    fn bit_reverse(&self, buf: &Self::Buf, n: usize, w: usize) -> Self::Buf;       // new buffer, rows permuted
    fn scale_pow(&self, buf: &mut Self::Buf, n: usize, w: usize, base: u64, uniform: u64); // x[r] *= uniform·base^r
    fn zero_extend(&self, buf: &Self::Buf, n: usize, w: usize, added_bits: usize) -> Self::Buf;
}
```
- `device::kernels` per-thread bodies (signatures below); `ntt::cpu::CpuNttEngine` (`Default`, `Clone`), `Buf = Vec<u64>`.

- [ ] **Step 1: Write the failing test**

```rust
// circuits/rand-zkvm-cuda/tests/ntt.rs
use p3_dft::{Radix2DitParallel, TwoAdicSubgroupDft};
use p3_field::{PrimeCharacteristicRing, PrimeField64, TwoAdicField};
use p3_goldilocks::Goldilocks;
use p3_matrix::Matrix;
use p3_matrix::dense::RowMajorMatrix;
use p3_util::reverse_bits_len;
use rand::{Rng, SeedableRng, rngs::StdRng};
use rand_zkvm_cuda::ntt::{cpu::CpuNttEngine, twiddles, NttEngine, LOG_MAX, LO_BITS};
use rand_zkvm_cuda::device::gl;

fn rand_mat(rng: &mut StdRng, n: usize, w: usize) -> Vec<u64> { (0..n * w).map(|_| rng.random::<u64>() % gl::P).collect() }

#[test]
fn twiddle_tables_reconstruct_powers() {
    let t = twiddles();
    let omega = Goldilocks::two_adic_generator(LOG_MAX).as_canonical_u64();
    for j in [0usize, 1, 2, 8191, 8192, 8193, 1 << 20, (1 << 25) - 1] {
        let expect = gl::pow(omega, j as u64);
        assert_eq!(gl::mul(t.lo[j & ((1 << LO_BITS) - 1)], t.hi[j >> LO_BITS]), expect, "j={j}");
        assert_eq!(gl::mul(t.inv_lo[j & ((1 << LO_BITS) - 1)], t.inv_hi[j >> LO_BITS]), gl::inv(expect));
    }
}

#[test]
fn dif_matches_plonky3_dft_bit_reversed() {
    let e = CpuNttEngine::default();
    let cpu = Radix2DitParallel::<Goldilocks>::default();
    let mut rng = StdRng::seed_from_u64(5);
    for log_n in [1usize, 2, 3, 9, 10, 11, 12, 15] {
        let n = 1 << log_n;
        for w in [1usize, 3, 7] {
            let vals = rand_mat(&mut rng, n, w);
            let mut buf = e.upload_row_major(&vals, n, w);
            e.dif(&mut buf, n, w, false);
            let ours = e.download_row_major(&buf, n, w);
            let expected = cpu.dft_batch(RowMajorMatrix::new(vals.iter().map(|&x| Goldilocks::from_u64(x)).collect(), w)).to_row_major_matrix();
            for r in 0..n { for c in 0..w {
                assert_eq!(ours[r * w + c], expected.get(reverse_bits_len(r, log_n), c).unwrap().as_canonical_u64(), "n={n} w={w} r={r} c={c}");
            } }
        }
    }
}

#[test]
fn inverse_dif_then_bit_reverse_recovers_coefficients() {
    let e = CpuNttEngine::default();
    let mut rng = StdRng::seed_from_u64(6);
    for log_n in [3usize, 10, 13] {
        let n = 1 << log_n; let w = 2;
        let coeffs = rand_mat(&mut rng, n, w);
        let mut buf = e.upload_row_major(&coeffs, n, w);
        e.dif(&mut buf, n, w, false);
        let evals = e.bit_reverse(&buf, n, w);            // natural-order evaluations
        let mut back = evals;
        e.dif(&mut back, n, w, true);
        let mut nat = e.bit_reverse(&back, n, w);
        e.scale_pow(&mut nat, n, w, 1, gl::inv(n as u64));
        assert_eq!(e.download_row_major(&nat, n, w), coeffs);
    }
}

#[test]
fn zero_extend_and_scale_pow() {
    let e = CpuNttEngine::default();
    let vals: Vec<u64> = (1..=8).collect(); // n=4, w=2 row-major: rows [1,2],[3,4],[5,6],[7,8]
    let buf = e.upload_row_major(&vals, 4, 2);
    let ext = e.zero_extend(&buf, 4, 2, 1);
    assert_eq!(e.download_row_major(&ext, 8, 2), vec![1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 0, 0, 0, 0, 0, 0]);
    let mut b2 = e.upload_row_major(&vals, 4, 2);
    e.scale_pow(&mut b2, 4, 2, 2, 3); // row r scaled by 3·2^r
    assert_eq!(e.download_row_major(&b2, 4, 2), vec![3, 6, 18, 24, 60, 72, 168, 192]);
}
```

- [ ] **Step 2: Run, expect compile failure.**

- [ ] **Step 3: Kernel bodies**

```rust
// circuits/rand-zkvm-cuda/src/device/kernels.rs
//! Per-thread bodies of every GPU kernel. `t` is the global thread index. Each body
//! writes only the element(s) owned by `t`, so running bodies for all `t` in any order
//! or in parallel gives the same result. The cuda-oxide crate wraps each in a
//! `#[kernel]`; the mock driver runs them in a loop.
use super::gl::{add, mul, pow, sub};
use super::poseidon2::{compress, hash_row};

pub const LO_BITS: usize = 13;
pub const LOG_MAX: usize = 26;
pub const LOG_TILE: usize = 10;

#[inline(always)]
fn rev(x: usize, bits: usize) -> usize { if bits == 0 { 0 } else { x.reverse_bits() >> (usize::BITS as usize - bits) } }

/// ω_n^j for the size-n NTT, n = 2^log_n, from the two-level ω_{2^26} tables.
#[inline(always)]
pub fn twiddle(lo: &[u64], hi: &[u64], j: usize, log_n: usize) -> u64 {
    let idx = j << (LOG_MAX - log_n);
    mul(lo[idx & ((1 << LO_BITS) - 1)], hi[idx >> LO_BITS])
}

/// data[t] *= uniform · base^(t mod n)   (column-major, so t mod n is the row)
pub fn scale_pow(t: usize, data: &mut [u64], n: usize, base: u64, uniform: u64) {
    if t >= data.len() { return; }
    let r = (t % n) as u64;
    data[t] = mul(data[t], mul(uniform, pow(base, r)));
}

/// dst[col*n + rev(row)] = src[col*n + row]
pub fn bit_reverse(t: usize, src: &[u64], dst: &mut [u64], n: usize, log_n: usize) {
    if t >= src.len() { return; }
    let col = t / n; let row = t % n;
    dst[col * n + rev(row, log_n)] = src[t];
}

/// dst (n_ext rows) = src (n rows) padded with zero rows, column-major.
pub fn zero_extend(t: usize, src: &[u64], dst: &mut [u64], n: usize, n_ext: usize) {
    if t >= dst.len() { return; }
    let col = t / n_ext; let row = t % n_ext;
    dst[t] = if row < n { src[col * n + row] } else { 0 };
}

/// row-major (rows × cols) → column-major
pub fn to_col_major(t: usize, src: &[u64], dst: &mut [u64], rows: usize, cols: usize) {
    if t >= src.len() { return; }
    let r = t / cols; let c = t % cols;
    dst[c * rows + r] = src[t];
}

/// column-major → row-major (rows × cols)
pub fn to_row_major(t: usize, src: &[u64], dst: &mut [u64], rows: usize, cols: usize) {
    if t >= src.len() { return; }
    let c = t / rows; let r = t % rows;
    dst[r * cols + c] = src[t];
}

/// One radix-2 DIF (Gentleman–Sande) stage with m = 2^s over `w` columns of height n.
/// Thread t handles butterfly t of the w·n/2 butterflies.
pub fn dif_stage(t: usize, data: &mut [u64], n: usize, log_n: usize, s: usize, lo: &[u64], hi: &[u64]) {
    let half_n = n / 2;
    if t >= (data.len() / n) * half_n { return; }
    let col = t / half_n; let b = t % half_n;
    let m = 1usize << s; let half = m / 2;
    let k = (b / half) * m; let j = b % half;
    let i0 = col * n + k + j; let i1 = i0 + half;
    let w = twiddle(lo, hi, j << (log_n - s), log_n); // ω_m^j = ω_n^{j·n/m}
    let u = data[i0]; let v = data[i1];
    data[i0] = add(u, v);
    data[i1] = mul(sub(u, v), w);
}

/// The stages s = log_tile..=1 of a DIF over one contiguous tile of 2^log_tile elements.
/// `t` is the thread within the tile (0..tile/2); call once per stage, with a barrier
/// between stages on the GPU.
pub fn dif_tile_stage(t: usize, tile: &mut [u64], log_n: usize, s: usize, lo: &[u64], hi: &[u64]) {
    let m = 1usize << s; let half = m / 2;
    if t >= tile.len() / 2 { return; }
    let k = (t / half) * m; let j = t % half;
    let i0 = k + j; let i1 = i0 + half;
    let w = twiddle(lo, hi, j << (log_n - s), log_n);
    let u = tile[i0]; let v = tile[i1];
    tile[i0] = add(u, v);
    tile[i1] = mul(sub(u, v), w);
}

/// Copy `n` rows of a `src_w`-wide row-major matrix into columns [col_off, col_off+src_w)
/// of a `dst_w`-wide row-major matrix.
pub fn copy_columns(t: usize, src: &[u64], src_w: usize, dst: &mut [u64], dst_w: usize, col_off: usize) {
    if t >= src.len() { return; }
    let r = t / src_w; let c = t % src_w;
    dst[r * dst_w + col_off + c] = src[t];
}

/// out[4t..4t+4] = sponge(row t of a `width`-wide row-major matrix)
pub fn poseidon2_rows(t: usize, rows: &[u64], width: usize, n: usize, k: &[u64], out: &mut [u64]) {
    if t >= n { return; }
    let d = hash_row(&rows[t * width..(t + 1) * width], k);
    out[4 * t..4 * t + 4].copy_from_slice(&d);
}

/// out[t] = compress(prev[2t], prev[2t+1]) for t < next_len (digests are 4 u64 each)
pub fn poseidon2_compress(t: usize, prev: &[u64], next_len: usize, k: &[u64], out: &mut [u64]) {
    if t >= next_len { return; }
    let a: [u64; 4] = prev[8 * t..8 * t + 4].try_into().unwrap();
    let b: [u64; 4] = prev[8 * t + 4..8 * t + 8].try_into().unwrap();
    out[4 * t..4 * t + 4].copy_from_slice(&compress(&a, &b, k));
}

/// Plonky3 `compress_and_inject` for arity 2: for t < raw_next, d = compress(prev pair);
/// r = hash(row t) if t < n_rows else zero digest; out[t] = compress(d, r).
pub fn poseidon2_inject(t: usize, prev: &[u64], raw_next: usize, rows: &[u64], width: usize, n_rows: usize, k: &[u64], out: &mut [u64]) {
    if t >= raw_next { return; }
    let a: [u64; 4] = prev[8 * t..8 * t + 4].try_into().unwrap();
    let b: [u64; 4] = prev[8 * t + 4..8 * t + 8].try_into().unwrap();
    let d = compress(&a, &b, k);
    let r = if t < n_rows { hash_row(&rows[t * width..(t + 1) * width], k) } else { [0u64; 4] };
    out[4 * t..4 * t + 4].copy_from_slice(&compress(&d, &r, k));
}
```

- [ ] **Step 4: Engine trait, twiddles, CPU engine**

```rust
// circuits/rand-zkvm-cuda/src/ntt/mod.rs
pub mod cpu;
use p3_field::{PrimeField64, TwoAdicField};
use p3_goldilocks::Goldilocks;
use crate::device::gl;
pub use crate::device::kernels::{LOG_MAX, LO_BITS, LOG_TILE};

pub struct Twiddles { pub lo: Vec<u64>, pub hi: Vec<u64>, pub inv_lo: Vec<u64>, pub inv_hi: Vec<u64> }

fn table(base: u64, len: usize) -> Vec<u64> {
    let mut v = Vec::with_capacity(len); let mut acc = 1u64;
    for _ in 0..len { v.push(acc); acc = gl::mul(acc, base); }
    v
}

pub fn twiddles() -> Twiddles {
    let omega = Goldilocks::two_adic_generator(LOG_MAX).as_canonical_u64();
    let omega_inv = gl::inv(omega);
    let lo_len = 1 << LO_BITS;
    let hi_len = 1 << (LOG_MAX - LO_BITS);
    Twiddles {
        lo: table(omega, lo_len), hi: table(gl::pow(omega, lo_len as u64), hi_len),
        inv_lo: table(omega_inv, lo_len), inv_hi: table(gl::pow(omega_inv, lo_len as u64), hi_len),
    }
}

pub trait NttEngine: Clone + Send + Sync + 'static {
    type Buf;
    fn max_columns(&self, n: usize) -> usize;
    fn upload_row_major(&self, values: &[u64], n: usize, w: usize) -> Self::Buf;
    fn download_row_major(&self, buf: &Self::Buf, n: usize, w: usize) -> Vec<u64>;
    fn dif(&self, buf: &mut Self::Buf, n: usize, w: usize, inverse: bool);
    fn bit_reverse(&self, buf: &Self::Buf, n: usize, w: usize) -> Self::Buf;
    fn scale_pow(&self, buf: &mut Self::Buf, n: usize, w: usize, base: u64, uniform: u64);
    fn zero_extend(&self, buf: &Self::Buf, n: usize, w: usize, added_bits: usize) -> Self::Buf;
}
```

```rust
// circuits/rand-zkvm-cuda/src/ntt/cpu.rs
use std::sync::Arc;
use p3_util::log2_strict_usize;
use super::{twiddles, NttEngine, Twiddles, LOG_TILE};
use crate::device::kernels as k;

#[derive(Clone)]
pub struct CpuNttEngine { tw: Arc<Twiddles> }
impl Default for CpuNttEngine { fn default() -> Self { Self { tw: Arc::new(twiddles()) } } }

impl NttEngine for CpuNttEngine {
    type Buf = Vec<u64>;
    fn max_columns(&self, _n: usize) -> usize { usize::MAX }
    fn upload_row_major(&self, values: &[u64], n: usize, w: usize) -> Vec<u64> {
        let mut dst = vec![0u64; n * w];
        for t in 0..n * w { k::to_col_major(t, values, &mut dst, n, w); }
        dst
    }
    fn download_row_major(&self, buf: &Vec<u64>, n: usize, w: usize) -> Vec<u64> {
        let mut dst = vec![0u64; n * w];
        for t in 0..n * w { k::to_row_major(t, buf, &mut dst, n, w); }
        dst
    }
    fn dif(&self, buf: &mut Vec<u64>, n: usize, w: usize, inverse: bool) {
        let log_n = log2_strict_usize(n);
        let (lo, hi) = if inverse { (&self.tw.inv_lo, &self.tw.inv_hi) } else { (&self.tw.lo, &self.tw.hi) };
        let log_tile = LOG_TILE.min(log_n);
        for s in ((log_tile + 1)..=log_n).rev() {
            for t in 0..w * n / 2 { k::dif_stage(t, buf, n, log_n, s, lo, hi); }
        }
        let tile = 1 << log_tile;
        for tile_start in (0..w * n).step_by(tile) {
            let chunk = &mut buf[tile_start..tile_start + tile];
            for s in (1..=log_tile).rev() { for t in 0..tile / 2 { k::dif_tile_stage(t, chunk, log_n, s, lo, hi); } }
        }
    }
    fn bit_reverse(&self, buf: &Vec<u64>, n: usize, w: usize) -> Vec<u64> {
        let mut dst = vec![0u64; n * w];
        for t in 0..n * w { k::bit_reverse(t, buf, &mut dst, n, log2_strict_usize(n)); }
        dst
    }
    fn scale_pow(&self, buf: &mut Vec<u64>, n: usize, _w: usize, base: u64, uniform: u64) {
        for t in 0..buf.len() { k::scale_pow(t, buf, n, base, uniform); }
    }
    fn zero_extend(&self, buf: &Vec<u64>, n: usize, w: usize, added_bits: usize) -> Vec<u64> {
        let n_ext = n << added_bits;
        let mut dst = vec![0u64; n_ext * w];
        for t in 0..n_ext * w { k::zero_extend(t, buf, &mut dst, n, n_ext); }
        dst
    }
}
```
Add `pub mod kernels;` to `device/mod.rs` and `pub mod ntt;` to `lib.rs`.

- [ ] **Step 5: Run `cargo test --test ntt`, expect pass.** If `dif_matches_plonky3_dft_bit_reversed` fails at `log_n ≥ 11` only, the tile handling is wrong (stages `> log_tile` must run before the tile pass).

- [ ] **Step 6: Commit** — `git commit -m "cuda: NTT engine trait, shared kernel bodies, CPU engine equal to Plonky3 DFT"`.

---

### Task 4: `Dft<E>` implementing `TwoAdicSubgroupDft<Goldilocks>`

**Files:**
- Create: `src/dft.rs`; Modify: `src/lib.rs` (`pub mod dft;`)
- Test: `tests/dft.rs`

**Interfaces:**
- Produces: `pub struct Dft<E: NttEngine>(pub Arc<E>)`, `impl<E: NttEngine + Default> Default`, `impl Clone`, `impl TwoAdicSubgroupDft<Goldilocks>` with `type Evaluations = BitReversedMatrixView<RowMajorMatrix<Goldilocks>>`; overrides `dft_batch`, `idft_batch`, `coset_lde_batch`, `coset_idft_batch`.

- [ ] **Step 1: Failing test**

```rust
// circuits/rand-zkvm-cuda/tests/dft.rs
use p3_dft::{Radix2DitParallel, TwoAdicSubgroupDft};
use p3_field::{Field, PrimeCharacteristicRing};
use p3_goldilocks::Goldilocks;
use p3_matrix::Matrix;
use p3_matrix::dense::RowMajorMatrix;
use rand::{Rng, SeedableRng, rngs::StdRng};
use rand_zkvm_cuda::dft::Dft;
use rand_zkvm_cuda::ntt::cpu::CpuNttEngine;

fn mat(rng: &mut StdRng, n: usize, w: usize) -> RowMajorMatrix<Goldilocks> {
    RowMajorMatrix::new((0..n * w).map(|_| Goldilocks::from_u64(rng.random::<u64>() % 0xFFFF_FFFF_0000_0001)).collect(), w)
}

#[test]
fn every_entry_point_matches_radix2dit_parallel() {
    let ours = Dft::<CpuNttEngine>::default();
    let theirs = Radix2DitParallel::<Goldilocks>::default();
    let mut rng = StdRng::seed_from_u64(11);
    let shift = Goldilocks::GENERATOR;
    for log_n in [1usize, 2, 5, 10, 11, 14] {
        let n = 1 << log_n;
        for w in [1usize, 5, 56] {
            let m = mat(&mut rng, n, w);
            assert_eq!(ours.dft_batch(m.clone()).to_row_major_matrix(), theirs.dft_batch(m.clone()).to_row_major_matrix(), "dft n={n} w={w}");
            assert_eq!(ours.idft_batch(m.clone()), theirs.idft_batch(m.clone()), "idft n={n} w={w}");
            for added in [1usize, 3, 4] {
                assert_eq!(ours.coset_lde_batch(m.clone(), added, shift).to_row_major_matrix(),
                           theirs.coset_lde_batch(m.clone(), added, shift).to_row_major_matrix(), "lde n={n} w={w} added={added}");
            }
            assert_eq!(ours.coset_idft_batch(m.clone(), shift), theirs.coset_idft_batch(m.clone(), shift), "coset_idft n={n} w={w}");
        }
    }
}

#[test]
fn column_chunking_gives_identical_results() {
    // A chunking engine that admits 3 columns at a time must give the same answer.
    #[derive(Clone, Default)] struct Narrow(CpuNttEngine);
    impl rand_zkvm_cuda::ntt::NttEngine for Narrow {
        type Buf = Vec<u64>;
        fn max_columns(&self, _n: usize) -> usize { 3 }
        fn upload_row_major(&self, v: &[u64], n: usize, w: usize) -> Vec<u64> { self.0.upload_row_major(v, n, w) }
        fn download_row_major(&self, b: &Vec<u64>, n: usize, w: usize) -> Vec<u64> { self.0.download_row_major(b, n, w) }
        fn dif(&self, b: &mut Vec<u64>, n: usize, w: usize, inv: bool) { self.0.dif(b, n, w, inv) }
        fn bit_reverse(&self, b: &Vec<u64>, n: usize, w: usize) -> Vec<u64> { self.0.bit_reverse(b, n, w) }
        fn scale_pow(&self, b: &mut Vec<u64>, n: usize, w: usize, base: u64, u: u64) { self.0.scale_pow(b, n, w, base, u) }
        fn zero_extend(&self, b: &Vec<u64>, n: usize, w: usize, k: usize) -> Vec<u64> { self.0.zero_extend(b, n, w, k) }
    }
    let narrow = Dft::<Narrow>::default();
    let wide = Dft::<CpuNttEngine>::default();
    let mut rng = StdRng::seed_from_u64(12);
    let m = mat(&mut rng, 64, 10);
    assert_eq!(narrow.coset_lde_batch(m.clone(), 2, Goldilocks::GENERATOR).to_row_major_matrix(),
               wide.coset_lde_batch(m, 2, Goldilocks::GENERATOR).to_row_major_matrix());
}
```

- [ ] **Step 2: Run, expect failure.**

- [ ] **Step 3: Implement**

```rust
// circuits/rand-zkvm-cuda/src/dft.rs
use std::sync::Arc;
use p3_dft::TwoAdicSubgroupDft;
use p3_field::{Field, PrimeCharacteristicRing, PrimeField64};
use p3_goldilocks::Goldilocks;
use p3_matrix::Matrix;
use p3_matrix::bitrev::{BitReversalPerm, BitReversedMatrixView};
use p3_matrix::dense::RowMajorMatrix;
use crate::device::gl;
use crate::ntt::NttEngine;

pub struct Dft<E: NttEngine>(pub Arc<E>);
impl<E: NttEngine> Clone for Dft<E> { fn clone(&self) -> Self { Dft(self.0.clone()) } }
impl<E: NttEngine + Default> Default for Dft<E> { fn default() -> Self { Dft(Arc::new(E::default())) } }

fn raw(m: &RowMajorMatrix<Goldilocks>) -> Vec<u64> { m.values.iter().map(|x| x.as_canonical_u64()).collect() }
fn wrap(v: Vec<u64>, w: usize) -> RowMajorMatrix<Goldilocks> { RowMajorMatrix::new(v.into_iter().map(Goldilocks::from_u64).collect(), w) }

/// Extract columns [c0, c1) of a row-major n×w matrix as a row-major n×(c1-c0) matrix.
fn columns(values: &[u64], w: usize, c0: usize, c1: usize) -> Vec<u64> {
    let n = values.len() / w;
    let mut out = Vec::with_capacity(n * (c1 - c0));
    for r in 0..n { out.extend_from_slice(&values[r * w + c0..r * w + c1]); }
    out
}
/// Write a row-major n×(c1-c0) block into columns [c0, c1) of a row-major n×w matrix.
fn place(dst: &mut [u64], w: usize, c0: usize, c1: usize, block: &[u64]) {
    let n = dst.len() / w; let bw = c1 - c0;
    for r in 0..n { dst[r * w + c0..r * w + c1].copy_from_slice(&block[r * bw..(r + 1) * bw]); }
}

impl<E: NttEngine> Dft<E> {
    /// Run `f` over column chunks that fit the engine; `f` maps an n_in×wc block to an n_out×wc block.
    fn chunked(&self, values: &[u64], w: usize, n_in: usize, n_out: usize, f: impl Fn(&[u64], usize) -> Vec<u64>) -> Vec<u64> {
        let max = self.0.max_columns(n_out.max(n_in)).max(1);
        if w <= max { return f(values, w); }
        let mut out = vec![0u64; n_out * w];
        let mut c0 = 0;
        while c0 < w {
            let c1 = (c0 + max).min(w);
            let block = f(&columns(values, w, c0, c1), c1 - c0);
            place(&mut out, w, c0, c1, &block);
            c0 = c1;
        }
        out
    }
    /// natural coefficients (row-major) ← natural evaluations (row-major), scaled by n⁻¹ and shift⁻ⁱ
    fn inverse_block(&self, block: &[u64], n: usize, wc: usize, shift_inv: u64) -> Vec<u64> {
        let e = &self.0;
        let mut buf = e.upload_row_major(block, n, wc);
        e.dif(&mut buf, n, wc, true);
        let mut nat = e.bit_reverse(&buf, n, wc);
        e.scale_pow(&mut nat, n, wc, shift_inv, gl::inv(n as u64));
        e.download_row_major(&nat, n, wc)
    }
}

impl<E: NttEngine> TwoAdicSubgroupDft<Goldilocks> for Dft<E> {
    type Evaluations = BitReversedMatrixView<RowMajorMatrix<Goldilocks>>;

    fn dft_batch(&self, mat: RowMajorMatrix<Goldilocks>) -> Self::Evaluations {
        let (n, w) = (mat.height(), mat.width());
        let out = self.chunked(&raw(&mat), w, n, n, |block, wc| {
            let mut buf = self.0.upload_row_major(block, n, wc);
            self.0.dif(&mut buf, n, wc, false);
            self.0.download_row_major(&buf, n, wc)
        });
        BitReversalPerm::new_view(wrap(out, w))
    }

    fn idft_batch(&self, mat: RowMajorMatrix<Goldilocks>) -> RowMajorMatrix<Goldilocks> {
        let (n, w) = (mat.height(), mat.width());
        wrap(self.chunked(&raw(&mat), w, n, n, |b, wc| self.inverse_block(b, n, wc, 1)), w)
    }

    fn coset_idft_batch(&self, mat: RowMajorMatrix<Goldilocks>, shift: Goldilocks) -> RowMajorMatrix<Goldilocks> {
        let (n, w) = (mat.height(), mat.width());
        let s_inv = shift.inverse().as_canonical_u64();
        wrap(self.chunked(&raw(&mat), w, n, n, |b, wc| self.inverse_block(b, n, wc, s_inv)), w)
    }

    fn coset_lde_batch(&self, mat: RowMajorMatrix<Goldilocks>, added_bits: usize, shift: Goldilocks) -> Self::Evaluations {
        let (n, w) = (mat.height(), mat.width());
        let n_ext = n << added_bits;
        let s = shift.as_canonical_u64();
        let out = self.chunked(&raw(&mat), w, n, n_ext, |block, wc| {
            let e = &self.0;
            let mut buf = e.upload_row_major(block, n, wc);
            e.dif(&mut buf, n, wc, true);
            let mut coeffs = e.bit_reverse(&buf, n, wc);
            e.scale_pow(&mut coeffs, n, wc, 1, gl::inv(n as u64));
            let mut ext = e.zero_extend(&coeffs, n, wc, added_bits);
            e.scale_pow(&mut ext, n_ext, wc, s, 1);
            e.dif(&mut ext, n_ext, wc, false);
            e.download_row_major(&ext, n_ext, wc)
        });
        BitReversalPerm::new_view(wrap(out, w))
    }
}
```

- [ ] **Step 4: Run `cargo test --test dft`, expect pass.**
- [ ] **Step 5: Commit** — `git commit -m "cuda: Dft<E> implements TwoAdicSubgroupDft over any NTT engine, equal to Radix2DitParallel"`.

---

### Task 5: Hash engine, layer plan, tree construction (non-hiding equality)

**Files:**
- Create: `src/merkle/mod.rs`, `src/merkle/cpu.rs`; Modify: `src/lib.rs`
- Test: `tests/merkle_tree.rs`

**Interfaces:**
- Produces:
```rust
pub type Digest = [u64; 4];
pub trait HashEngine: Clone + Send + Sync + 'static {
    type Mat;   // row-major matrix on device
    type Dig;   // digest layer on device (4 u64 per digest)
    fn upload(&self, values: &[u64], width: usize) -> Self::Mat;
    fn concat(&self, parts: &[(&Self::Mat, usize)], n: usize) -> (Self::Mat, usize);  // side-by-side, returns (mat, total width)
    fn hash_rows(&self, rows: &Self::Mat, width: usize, n: usize, out_len: usize) -> Self::Dig; // out_len ≥ n, extra digests zero
    fn compress(&self, prev: &Self::Dig, next_len: usize, out_len: usize) -> Self::Dig;
    fn inject(&self, prev: &Self::Dig, raw_next: usize, rows: &Self::Mat, width: usize, n_rows: usize, out_len: usize) -> Self::Dig;
    fn download(&self, dig: &Self::Dig) -> Vec<Digest>;
}
pub struct Plan { pub order: Vec<usize>, pub layers: Vec<Vec<usize>> }  // order: matrix indices tallest first (stable); layers[l]: matrices injected when building digest layer l+1
pub fn plan(heights: &[usize]) -> Plan;
pub fn padded_len(raw: usize) -> usize;   // Plonky3 padded_len(raw, 2)
pub struct Tree { pub digest_layers: Vec<Vec<Digest>>, pub arity_schedule: Vec<usize> }
pub fn build_tree<E: HashEngine>(engine: &E, mats: &[(&E::Mat, usize /*width*/, usize /*height*/)]) -> Tree;
pub fn cap(tree: &Tree, cap_height: usize) -> Vec<Digest>;   // Plonky3 MerkleTree::cap with effective cap height
```
- `merkle::cpu::CpuHashEngine::new(perm_seed: u64)` with `Mat = Vec<u64>`, `Dig = Vec<u64>`.

- [ ] **Step 1: Failing test**

```rust
// circuits/rand-zkvm-cuda/tests/merkle_tree.rs
use p3_commit::Mmcs;
use p3_field::{Field, PrimeCharacteristicRing, PrimeField64};
use p3_goldilocks::{Goldilocks, Poseidon2Goldilocks};
use p3_matrix::dense::RowMajorMatrix;
use p3_merkle_tree::MerkleTreeMmcs;
use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};
use rand::{Rng, SeedableRng, rngs::StdRng};
use rand_zkvm_cuda::merkle::{build_tree, cap, cpu::CpuHashEngine, plan, HashEngine};

const SEED: u64 = 0x5261_6e64_5a4b;
type Perm = Poseidon2Goldilocks<8>;
type Hash = PaddingFreeSponge<Perm, 8, 4, 4>;
type Compress = TruncatedPermutation<Perm, 2, 4, 8>;
type Packing = <Goldilocks as Field>::Packing;
type Mmcs3 = MerkleTreeMmcs<Packing, Packing, Hash, Compress, 2, 4>;

fn mmcs() -> Mmcs3 { let p = Perm::new_from_rng_128(&mut StdRng::seed_from_u64(SEED)); Mmcs3::new(Hash::new(p.clone()), Compress::new(p), 2) }
fn rand_mat(rng: &mut StdRng, h: usize, w: usize) -> Vec<u64> { (0..h * w).map(|_| rng.random::<u64>() % 0xFFFF_FFFF_0000_0001).collect() }
fn to_p3(v: &[u64], w: usize) -> RowMajorMatrix<Goldilocks> { RowMajorMatrix::new(v.iter().map(|&x| Goldilocks::from_u64(x)).collect(), w) }

#[test]
fn plan_orders_tallest_first_stably_and_injects_at_matching_layers() {
    let p = plan(&[16, 64, 16, 8, 64]);
    assert_eq!(p.order, vec![1, 4, 0, 2, 3]);
    // layer 0 = leaves of the 64-high matrices; next layers 32, 16 (inject 0,2), 8 (inject 3), 4, 2, 1
    assert_eq!(p.layers, vec![vec![], vec![0, 2], vec![3], vec![], vec![], vec![]]);
}

#[test]
fn caps_equal_plonky3_for_every_tier_shape() {
    let e = CpuHashEngine::new(SEED);
    let m = mmcs();
    let mut rng = StdRng::seed_from_u64(21);
    // (heights, widths) shaped like the batch STARK at tier 10 after a ×16 hiding blowup: cpu, alu, mem, byte, program, random
    let shapes: Vec<Vec<(usize, usize)>> = vec![
        vec![(1 << 14, 56), (1 << 15, 24), (1 << 16, 16), (1 << 16, 8), (1 << 10, 6), (1 << 16, 1)],
        vec![(1 << 4, 3)],
        vec![(1 << 5, 2), (1 << 5, 7), (1 << 3, 1)],
        vec![(1 << 6, 1), (1 << 2, 4)],
    ];
    for shape in shapes {
        let mats: Vec<(Vec<u64>, usize, usize)> = shape.iter().map(|&(h, w)| (rand_mat(&mut rng, h, w), w, h)).collect();
        let (theirs_cap, _) = m.commit(mats.iter().map(|(v, w, _)| to_p3(v, *w)).collect());
        let up: Vec<_> = mats.iter().map(|(v, w, _)| e.upload(v, *w)).collect();
        let refs: Vec<_> = up.iter().zip(&mats).map(|(u, (_, w, h))| (u, *w, *h)).collect();
        let tree = build_tree(&e, &refs);
        let ours = cap(&tree, 2);
        let theirs: Vec<[u64; 4]> = theirs_cap.roots().iter().map(|d| d.map(|x| x.as_canonical_u64())).collect();
        assert_eq!(ours, theirs, "shape {shape:?}");
    }
}
```

- [ ] **Step 2: Run, expect failure.**

- [ ] **Step 3: Implement**

```rust
// circuits/rand-zkvm-cuda/src/merkle/mod.rs
pub mod cpu;
pub mod prune;
pub mod mmcs;
pub type Digest = [u64; 4];

pub trait HashEngine: Clone + Send + Sync + 'static {
    type Mat; type Dig;
    fn upload(&self, values: &[u64], width: usize) -> Self::Mat;
    fn concat(&self, parts: &[(&Self::Mat, usize)], n: usize) -> (Self::Mat, usize);
    fn hash_rows(&self, rows: &Self::Mat, width: usize, n: usize, out_len: usize) -> Self::Dig;
    fn compress(&self, prev: &Self::Dig, next_len: usize, out_len: usize) -> Self::Dig;
    fn inject(&self, prev: &Self::Dig, raw_next: usize, rows: &Self::Mat, width: usize, n_rows: usize, out_len: usize) -> Self::Dig;
    fn download(&self, dig: &Self::Dig) -> Vec<Digest>;
}

/// Plonky3 `padded_len(raw_len, 2)`.
pub const fn padded_len(raw: usize) -> usize { if raw <= 1 { raw } else { raw.div_ceil(2) * 2 } }

pub struct Plan { pub order: Vec<usize>, pub layers: Vec<Vec<usize>> }

/// Mirror of `MerkleTree::new` scheduling for N = 2 (every step is 2).
pub fn plan(heights: &[usize]) -> Plan {
    let mut order: Vec<usize> = (0..heights.len()).collect();
    order.sort_by_key(|&i| std::cmp::Reverse(heights[i])); // stable
    let max = heights[order[0]];
    let mut pos = order.iter().position(|&i| heights[i] != max).unwrap_or(order.len());
    let mut layers = Vec::new();
    let mut len = padded_len(max);
    while len > 1 {
        let next_len = (len / 2).next_power_of_two();
        let mut inject = Vec::new();
        while pos < order.len() && heights[order[pos]].next_power_of_two() == next_len { inject.push(order[pos]); pos += 1; }
        layers.push(inject);
        let raw_next = len / 2;
        len = if inject_is_empty_len(raw_next) { padded_len(raw_next) } else { padded_len(raw_next) };
    }
    Plan { order, layers }
}
#[inline] fn inject_is_empty_len(x: usize) -> bool { let _ = x; true }

pub struct Tree { pub digest_layers: Vec<Vec<Digest>>, pub arity_schedule: Vec<usize> }

/// `mats[i] = (device matrix, width, height)` in commit order.
pub fn build_tree<E: HashEngine>(e: &E, mats: &[(&E::Mat, usize, usize)]) -> Tree {
    let heights: Vec<usize> = mats.iter().map(|m| m.2).collect();
    let p = plan(&heights);
    let max = heights[p.order[0]];
    let tallest: Vec<usize> = p.order.iter().copied().take_while(|&i| heights[i] == max).collect();
    let group = |idx: &[usize]| -> (E::Mat, usize) {
        let parts: Vec<(&E::Mat, usize)> = idx.iter().map(|&i| (mats[i].0, mats[i].1)).collect();
        e.concat(&parts, heights[idx[0]])
    };
    let (leaf_mat, leaf_w) = group(&tallest);
    let mut dig = e.hash_rows(&leaf_mat, leaf_w, max, padded_len(max));
    let mut layers = vec![e.download(&dig)];
    let mut prev_len = padded_len(max);
    for inject in &p.layers {
        let raw_next = prev_len / 2;
        let out_len = padded_len(raw_next);
        dig = if inject.is_empty() {
            e.compress(&dig, raw_next, out_len)
        } else {
            let (m, w) = group(inject);
            e.inject(&dig, raw_next, &m, w, heights[inject[0]], out_len)
        };
        layers.push(e.download(&dig));
        prev_len = out_len;
    }
    let n = layers.len() - 1;
    Tree { digest_layers: layers, arity_schedule: vec![2; n] }
}

/// Plonky3 `MerkleTreeMmcs::commit` cap: effective cap height = min(cap_height, num_layers - 1);
/// cap = digest_layers[num_layers - 1 - h][..min(2^h, layer len)].
pub fn cap(tree: &Tree, cap_height: usize) -> Vec<Digest> {
    let num_layers = tree.digest_layers.len();
    let h = cap_height.min(num_layers.saturating_sub(1));
    let layer = &tree.digest_layers[num_layers - 1 - h];
    let len = (1usize << h).min(layer.len());
    layer[..len].to_vec()
}
```
Simplify `plan`: replace the `len = ...` line with `len = padded_len(raw_next);` and delete `inject_is_empty_len`. (Left explicit here so the mirror of Plonky3's loop — `next_layer_len = (prev_len / step).next_power_of_two()` for injection matching, `padded_len(raw_next)` for the stored layer length — is visible.)

```rust
// circuits/rand-zkvm-cuda/src/merkle/cpu.rs
use std::sync::Arc;
use super::{Digest, HashEngine};
use crate::device::kernels as k;

#[derive(Clone)]
pub struct CpuHashEngine { k: Arc<[u64; crate::device::poseidon2::N_CONSTS]> }
impl CpuHashEngine { pub fn new(perm_seed: u64) -> Self { Self { k: Arc::new(crate::constants::poseidon2_constants(perm_seed)) } } }

impl HashEngine for CpuHashEngine {
    type Mat = Vec<u64>; type Dig = Vec<u64>;
    fn upload(&self, values: &[u64], _width: usize) -> Vec<u64> { values.to_vec() }
    fn concat(&self, parts: &[(&Vec<u64>, usize)], n: usize) -> (Vec<u64>, usize) {
        if parts.len() == 1 { return (parts[0].0.clone(), parts[0].1); }
        let total: usize = parts.iter().map(|p| p.1).sum();
        let mut dst = vec![0u64; n * total];
        let mut off = 0;
        for (src, w) in parts { for t in 0..src.len() { k::copy_columns(t, src, *w, &mut dst, total, off); } off += w; }
        (dst, total)
    }
    fn hash_rows(&self, rows: &Vec<u64>, width: usize, n: usize, out_len: usize) -> Vec<u64> {
        let mut out = vec![0u64; 4 * out_len];
        for t in 0..n { k::poseidon2_rows(t, rows, width, n, &self.k[..], &mut out); }
        out
    }
    fn compress(&self, prev: &Vec<u64>, next_len: usize, out_len: usize) -> Vec<u64> {
        let mut out = vec![0u64; 4 * out_len];
        for t in 0..next_len { k::poseidon2_compress(t, prev, next_len, &self.k[..], &mut out); }
        out
    }
    fn inject(&self, prev: &Vec<u64>, raw_next: usize, rows: &Vec<u64>, width: usize, n_rows: usize, out_len: usize) -> Vec<u64> {
        let mut out = vec![0u64; 4 * out_len];
        for t in 0..raw_next { k::poseidon2_inject(t, prev, raw_next, rows, width, n_rows, &self.k[..], &mut out); }
        out
    }
    fn download(&self, dig: &Vec<u64>) -> Vec<Digest> { dig.chunks_exact(4).map(|c| [c[0], c[1], c[2], c[3]]).collect() }
}
```
Create empty `src/merkle/prune.rs` and `src/merkle/mmcs.rs` so the module tree compiles; they are filled in Task 6. Add `pub mod merkle;` to `lib.rs`.

- [ ] **Step 4: Run `cargo test --test merkle_tree`, expect pass.** If the plan test fails, re-read Plonky3's `MerkleTree::new` loop in the spec's "CPU tree semantics" section: injection matches `height.next_power_of_two() == (prev_len / 2).next_power_of_two()`.
- [ ] **Step 5: Commit** — `git commit -m "cuda: hash engine, layer plan and tree builder; caps equal Plonky3 MerkleTreeMmcs"`.

---

### Task 6: `HidingMmcs<E>` with openings, pruned multi-proofs, delegated verification

**Files:**
- Create: `src/merkle/prune.rs`, `src/merkle/mmcs.rs`
- Test: `tests/hiding_mmcs.rs`

**Interfaces:**
- Produces:
```rust
pub type Val = Goldilocks;
pub type Perm = Poseidon2Goldilocks<8>;
pub type Hash = PaddingFreeSponge<Perm, 8, 4, 4>;
pub type Compress = TruncatedPermutation<Perm, 2, 4, 8>;
pub type Packing = <Val as Field>::Packing;
pub type P3Hiding = MerkleTreeHidingMmcs<Packing, Packing, Hash, Compress, StdRng, 2, 4, 4>;
pub const SALT_ELEMS: usize = 4;
pub struct HidingMmcs<E: HashEngine> { .. }
impl<E: HashEngine> HidingMmcs<E> { pub fn new(engine: Arc<E>, perm_seed: u64, cap_height: usize, rng: StdRng) -> Self; }
pub struct ProverData<M> { pub originals: Vec<M>, pub salted: Vec<RowMajorMatrix<Val>>, pub tree: Tree }
impl<E: HashEngine> Mmcs<Val> for HidingMmcs<E> { type ProverData<M> = ProverData<M>; type Commitment = MerkleCap<Val, [Val; 4]>; type Proof = (Vec<Vec<Val>>, Vec<[Val; 4]>); type MultiProof = (Vec<Vec<Vec<Val>>>, PrunedMerklePaths<Val, 4>); type Error = MerkleTreeError; .. }
```
- `prune::prune_paths(arity_schedule: &[usize], paths: &[(usize /*leaf*/, Vec<Digest>)]) -> Vec<Digest>` (the `sibling_hashes` in Plonky3 frontier order).

- [ ] **Step 1: Failing test**

```rust
// circuits/rand-zkvm-cuda/tests/hiding_mmcs.rs
use std::sync::Arc;
use p3_commit::{BatchOpeningRef, Mmcs};
use p3_field::PrimeCharacteristicRing;
use p3_goldilocks::Goldilocks;
use p3_matrix::{Dimensions, Matrix};
use p3_matrix::dense::RowMajorMatrix;
use rand::{Rng, SeedableRng, rngs::StdRng};
use rand_zkvm_cuda::merkle::cpu::CpuHashEngine;
use rand_zkvm_cuda::merkle::mmcs::{HidingMmcs, P3Hiding, Compress, Hash, Perm};

const SEED: u64 = 0x5261_6e64_5a4b;

fn p3(rng_seed: u64) -> P3Hiding { let p = Perm::new_from_rng_128(&mut StdRng::seed_from_u64(SEED)); P3Hiding::new(Hash::new(p.clone()), Compress::new(p), 2, StdRng::seed_from_u64(rng_seed)) }
fn ours(rng_seed: u64) -> HidingMmcs<CpuHashEngine> { HidingMmcs::new(Arc::new(CpuHashEngine::new(SEED)), SEED, 2, StdRng::seed_from_u64(rng_seed)) }
fn mats(rng: &mut StdRng, shape: &[(usize, usize)]) -> Vec<RowMajorMatrix<Goldilocks>> {
    shape.iter().map(|&(h, w)| RowMajorMatrix::new((0..h * w).map(|_| Goldilocks::from_u64(rng.random::<u64>() % 0xFFFF_FFFF_0000_0001)).collect(), w)).collect()
}
const SHAPES: [&[(usize, usize)]; 3] = [&[(64, 5), (64, 2), (16, 3), (8, 1)], &[(1 << 12, 56), (1 << 13, 20), (1 << 14, 12), (1 << 14, 1)], &[(2, 1)]];

#[test]
fn commit_equals_plonky3_with_same_salt_rng() {
    let mut rng = StdRng::seed_from_u64(31);
    for shape in SHAPES {
        let m = mats(&mut rng, shape);
        let (c1, _) = p3(77).commit(m.clone());
        let (c2, _) = ours(77).commit(m);
        assert_eq!(c1, c2, "{shape:?}");
    }
}

#[test]
fn plonky3_verifies_our_single_openings_and_rejects_tampering() {
    let mut rng = StdRng::seed_from_u64(32);
    for shape in SHAPES {
        let m = mats(&mut rng, shape);
        let dims: Vec<Dimensions> = m.iter().map(|x| x.dimensions()).collect();
        let o = ours(5);
        let (commit, pd) = o.commit(m);
        let max_h = dims.iter().map(|d| d.height).max().unwrap();
        for index in [0usize, 1, max_h / 2, max_h - 1] {
            let opening = o.open_batch(index, &pd);
            p3(0).verify_batch(&commit, &dims, index, BatchOpeningRef::new(&opening.opened_values, &opening.opening_proof)).unwrap();
            o.verify_batch(&commit, &dims, index, BatchOpeningRef::new(&opening.opened_values, &opening.opening_proof)).unwrap();
            let mut bad = opening.opened_values.clone();
            bad[0][0] += Goldilocks::ONE;
            assert!(p3(0).verify_batch(&commit, &dims, index, BatchOpeningRef::new(&bad, &opening.opening_proof)).is_err());
        }
    }
}

#[test]
fn plonky3_verifies_our_pruned_multi_openings() {
    let mut rng = StdRng::seed_from_u64(33);
    for shape in SHAPES {
        let m = mats(&mut rng, shape);
        let dims: Vec<Dimensions> = m.iter().map(|x| x.dimensions()).collect();
        let o = ours(6);
        let (commit, pd) = o.commit(m.clone());
        let max_h = dims.iter().map(|d| d.height).max().unwrap();
        let indices: Vec<usize> = (0..80).map(|_| rng.random::<u64>() as usize % max_h).collect();
        let (opened, proof) = o.open_multi_batch(&indices, &pd);
        p3(0).verify_multi_batch(&commit, &dims, &indices, &opened, &proof).unwrap();
        o.verify_multi_batch(&commit, &dims, &indices, &opened, &proof).unwrap();
        // Same salts ⇒ byte-identical multi proof to Plonky3's own.
        let (_, pd3) = p3(6).commit(m);
        let (opened3, proof3) = p3(6).open_multi_batch(&indices, &pd3);
        assert_eq!(postcard::to_allocvec(&(opened3, proof3)).unwrap(), postcard::to_allocvec(&(opened, proof)).unwrap());
    }
}

#[test]
fn get_matrices_returns_unsalted_originals() {
    let mut rng = StdRng::seed_from_u64(34);
    let m = mats(&mut rng, SHAPES[0]);
    let o = ours(1);
    let (_, pd) = o.commit(m.clone());
    let got = o.get_matrices(&pd);
    assert_eq!(got.len(), m.len());
    for (a, b) in got.iter().zip(&m) { assert_eq!(a.width(), b.width()); assert_eq!(**a, *b); }
    assert_eq!(o.get_max_height(&pd), 64);
}
```

- [ ] **Step 2: Run, expect failure.**

- [ ] **Step 3: Implement pruning (mirror of Plonky3 `prune_paths`)**

```rust
// circuits/rand-zkvm-cuda/src/merkle/prune.rs
//! Byte-for-byte mirror of p3-merkle-tree 0.7 `pruning.rs::prune_paths` + `walk_frontier`.
use super::Digest;

#[derive(Clone, Copy)]
struct Node { index: usize, lead: usize }

fn total_siblings(levels: usize, arity: &[usize]) -> usize { arity[..levels].iter().map(|a| a - 1).sum() }
const fn sibling_offset(k: usize, lead_pos: usize) -> usize { if k < lead_pos { k } else { k - 1 } }

fn walk_frontier(sorted_unique: &[usize], arity: &[usize], mut visit: impl FnMut(usize, usize, usize, usize)) {
    if sorted_unique.is_empty() { return; }
    let mut nodes: Vec<Node> = sorted_unique.iter().enumerate().map(|(slot, &index)| Node { index, lead: slot }).collect();
    let mut parents: Vec<Node> = Vec::with_capacity(nodes.len());
    for (level, &a) in arity.iter().enumerate() {
        parents.clear();
        let mut i = 0;
        while i < nodes.len() {
            let group = nodes[i].index / a;
            let group_start = group * a;
            let lead = nodes[i].lead;
            let lead_pos = nodes[i].index - group_start;
            let mut member = i;
            for k in 0..a {
                if member < nodes.len() && nodes[member].index == group_start + k { member += 1; } else { visit(level, lead, lead_pos, k); }
            }
            parents.push(Node { index: group, lead });
            i = member;
        }
        std::mem::swap(&mut nodes, &mut parents);
    }
}

/// `paths[i] = (leaf_index, full sibling list level 0 first)`. Returns Plonky3's `sibling_hashes`.
pub fn prune_paths(arity: &[usize], paths: &[(usize, Vec<Digest>)]) -> Vec<Digest> {
    let mut order: Vec<u32> = (0..paths.len() as u32).collect();
    order.sort_unstable_by_key(|&i| paths[i as usize].0);
    order.dedup_by_key(|&mut i| paths[i as usize].0);
    let sorted_unique: Vec<usize> = order.iter().map(|&i| paths[i as usize].0).collect();
    let chunk_base: Vec<usize> = (0..=arity.len()).map(|l| total_siblings(l, arity)).collect();
    let mut out = Vec::new();
    walk_frontier(&sorted_unique, arity, |level, lead, lead_pos, k| {
        let src = &paths[order[lead] as usize].1;
        out.push(src[chunk_base[level] + sibling_offset(k, lead_pos)]);
    });
    out
}
```

- [ ] **Step 4: Implement the Mmcs**

```rust
// circuits/rand-zkvm-cuda/src/merkle/mmcs.rs
use std::sync::{Arc, Mutex};
use p3_commit::{BatchOpening, BatchOpeningRef, Mmcs};
use p3_field::{Field, PrimeCharacteristicRing, PrimeField64};
use p3_goldilocks::{Goldilocks, Poseidon2Goldilocks};
use p3_matrix::{Dimensions, Matrix};
use p3_matrix::dense::RowMajorMatrix;
use p3_merkle_tree::{MerkleCap, MerkleTreeError, MerkleTreeHidingMmcs, PrunedMerklePaths};
use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};
use p3_util::log2_ceil_usize;
use rand::{SeedableRng, rngs::StdRng};
use super::{build_tree, cap, prune::prune_paths, Digest, HashEngine, Tree};

pub type Val = Goldilocks;
pub type Perm = Poseidon2Goldilocks<8>;
pub type Hash = PaddingFreeSponge<Perm, 8, 4, 4>;
pub type Compress = TruncatedPermutation<Perm, 2, 4, 8>;
pub type Packing = <Val as Field>::Packing;
pub type P3Hiding = MerkleTreeHidingMmcs<Packing, Packing, Hash, Compress, StdRng, 2, 4, 4>;
pub const SALT_ELEMS: usize = 4;

pub struct ProverData<M> { pub originals: Vec<M>, pub salted: Vec<RowMajorMatrix<Val>>, pub tree: Tree }

pub struct HidingMmcs<E: HashEngine> { engine: Arc<E>, verifier: P3Hiding, cap_height: usize, rng: Arc<Mutex<StdRng>> }
impl<E: HashEngine> Clone for HidingMmcs<E> {
    fn clone(&self) -> Self { Self { engine: self.engine.clone(), verifier: self.verifier.clone(), cap_height: self.cap_height, rng: self.rng.clone() } }
}
impl<E: HashEngine> HidingMmcs<E> {
    pub fn new(engine: Arc<E>, perm_seed: u64, cap_height: usize, rng: StdRng) -> Self {
        let perm = crate::constants::permutation(perm_seed);
        let verifier = P3Hiding::new(Hash::new(perm.clone()), Compress::new(perm), cap_height, StdRng::seed_from_u64(0));
        Self { engine, verifier, cap_height, rng: Arc::new(Mutex::new(rng)) }
    }
    fn digest(d: &Digest) -> [Val; 4] { d.map(Val::from_u64) }
    fn proof_levels(tree: &Tree, cap_height: usize) -> usize {
        let n = tree.digest_layers.len();
        n.saturating_sub(1).saturating_sub(cap_height.min(n.saturating_sub(1)))
    }
    /// Plonky3 `open_batch` over the salted leaves: rows (with salts) and full sibling path.
    fn open_raw<M: Matrix<Val>>(&self, index: usize, pd: &ProverData<M>) -> (Vec<Vec<Val>>, Vec<Digest>) {
        let max_h = pd.salted.iter().map(|m| m.height()).max().unwrap();
        assert!(index < max_h, "index {index} out of bounds for height {max_h}");
        let log_max = log2_ceil_usize(max_h);
        let rows = pd.salted.iter().map(|m| { let r = index >> (log_max - log2_ceil_usize(m.height())); m.row(r).unwrap().into_iter().collect() }).collect();
        let mut sib = Vec::new(); let mut idx = index;
        for l in 0..Self::proof_levels(&pd.tree, self.cap_height) {
            let step = pd.tree.arity_schedule[l];
            let gs = (idx / step) * step; let pos = idx % step;
            for k in 0..step { if k != pos { sib.push(pd.tree.digest_layers[l][gs + k]); } }
            idx /= step;
        }
        (rows, sib)
    }
    fn split_salt(row: Vec<Val>) -> (Vec<Val>, Vec<Val>) { let n = row.len() - SALT_ELEMS; let mut r = row; let s = r.split_off(n); (r, s) }
}

impl<E: HashEngine> Mmcs<Val> for HidingMmcs<E> {
    type ProverData<M> = ProverData<M>;
    type Commitment = MerkleCap<Val, [Val; 4]>;
    type Proof = (Vec<Vec<Val>>, Vec<[Val; 4]>);
    type MultiProof = (Vec<Vec<Vec<Val>>>, PrunedMerklePaths<Val, 4>);
    type Error = MerkleTreeError;

    fn commit<M: Matrix<Val>>(&self, inputs: Vec<M>) -> (Self::Commitment, ProverData<M>) {
        let mut rng = self.rng.lock().unwrap();
        let salted: Vec<RowMajorMatrix<Val>> = inputs.iter().map(|m| {
            let salts = RowMajorMatrix::<Val>::rand(&mut *rng, m.height(), SALT_ELEMS);
            let w = m.width() + SALT_ELEMS;
            let mut v = Vec::with_capacity(m.height() * w);
            for (r, row) in m.rows().enumerate() { v.extend(row); v.extend_from_slice(&salts.values[r * SALT_ELEMS..(r + 1) * SALT_ELEMS]); }
            RowMajorMatrix::new(v, w)
        }).collect();
        drop(rng);
        let ups: Vec<E::Mat> = salted.iter().map(|m| self.engine.upload(&m.values.iter().map(|x| x.as_canonical_u64()).collect::<Vec<_>>(), m.width())).collect();
        let refs: Vec<(&E::Mat, usize, usize)> = ups.iter().zip(&salted).map(|(u, m)| (u, m.width(), m.height())).collect();
        let tree = build_tree(&*self.engine, &refs);
        let commitment = MerkleCap::new(cap(&tree, self.cap_height).iter().map(Self::digest).collect());
        (commitment, ProverData { originals: inputs, salted, tree })
    }

    fn open_batch<M: Matrix<Val>>(&self, index: usize, pd: &ProverData<M>) -> BatchOpening<Val, Self> {
        let (rows, sib) = self.open_raw(index, pd);
        let (opened, salts): (Vec<_>, Vec<_>) = rows.into_iter().map(Self::split_salt).unzip();
        BatchOpening::new(opened, (salts, sib.iter().map(Self::digest).collect()))
    }

    fn get_matrices<'a, M: Matrix<Val>>(&self, pd: &'a ProverData<M>) -> Vec<&'a M> { pd.originals.iter().collect() }

    fn verify_batch(&self, commit: &Self::Commitment, dims: &[Dimensions], index: usize, opening: BatchOpeningRef<'_, Val, Self>) -> Result<(), MerkleTreeError> {
        let (values, proof) = opening.unpack();
        self.verifier.verify_batch(commit, dims, index, BatchOpeningRef::new(values, proof))
    }

    fn open_multi_batch<M: Matrix<Val>>(&self, indices: &[usize], pd: &ProverData<M>) -> (Vec<Vec<Vec<Val>>>, Self::MultiProof) {
        let levels = Self::proof_levels(&pd.tree, self.cap_height);
        let mut opened = Vec::with_capacity(indices.len()); let mut salts = Vec::with_capacity(indices.len()); let mut paths = Vec::with_capacity(indices.len());
        for &i in indices {
            let (rows, sib) = self.open_raw(i, pd);
            let (o, s): (Vec<_>, Vec<_>) = rows.into_iter().map(Self::split_salt).unzip();
            opened.push(o); salts.push(s); paths.push((i, sib));
        }
        let pruned = prune_paths(&pd.tree.arity_schedule[..levels], &paths);
        (opened, (salts, PrunedMerklePaths { sibling_hashes: pruned.iter().map(Self::digest).collect() }))
    }

    fn verify_multi_batch<R: AsRef<[Val]> + PartialEq>(&self, commit: &Self::Commitment, dims: &[Dimensions], indices: &[usize], opened: &[Vec<R>], proof: &Self::MultiProof) -> Result<(), MerkleTreeError> {
        self.verifier.verify_multi_batch(commit, dims, indices, opened, proof)
    }
}
```
If `self.verifier.verify_batch` will not accept `BatchOpeningRef<'_, Val, Self>` because the `Proof` associated types are distinct nominal types, they are the same tuple type, so construct `BatchOpeningRef::<Val, P3Hiding>::new(values, proof)` explicitly. Same for `verify_multi_batch`.

- [ ] **Step 5: Run `cargo test --test hiding_mmcs`, expect pass.** The byte-equality assertion in the multi-batch test is the strongest check; if only it fails, compare `sibling_hashes.len()` first (wrong `levels` slice), then order.
- [ ] **Step 6: Commit** — `git commit -m "cuda: HidingMmcs<E> with pruned multi-openings; Plonky3 verifies every opening, multi-proofs byte-identical"`.

---

### Task 7: cuda-oxide kernel crate

**Files:**
- Create: `circuits/gpu-kernels/Cargo.toml`, `rust-toolchain.toml`, `src/main.rs`, `Justfile`
- Create: `circuits/rand-zkvm-cuda/ptx/PTX_BUILD.md`

**Interfaces:**
- Produces PTX entry points (bare names, parameter order is the launch contract for Task 9): `scale_pow(data: DisjointSlice<u64>, n: u32, base: u64, uniform: u64)`, `bit_reverse(src: &[u64], dst: DisjointSlice<u64>, n: u32, log_n: u32)`, `zero_extend(src: &[u64], dst: DisjointSlice<u64>, n: u32, n_ext: u32)`, `to_col_major(src: &[u64], dst: DisjointSlice<u64>, rows: u32, cols: u32)`, `to_row_major(src, dst, rows, cols)`, `dif_stage(data: DisjointSlice<u64>, n: u32, log_n: u32, s: u32, lo: &[u64], hi: &[u64])`, `dif_tiles(data: DisjointSlice<u64>, n: u32, log_n: u32, log_tile: u32, lo: &[u64], hi: &[u64])` (block = tile/2 threads, one tile per block), `copy_columns(src: &[u64], src_w: u32, dst: DisjointSlice<u64>, dst_w: u32, col_off: u32)`, `poseidon2_rows(rows: &[u64], width: u32, n: u32, k: &[u64], out: DisjointSlice<u64>)`, `poseidon2_compress(prev: &[u64], next_len: u32, k: &[u64], out: DisjointSlice<u64>)`, `poseidon2_inject(prev: &[u64], raw_next: u32, rows: &[u64], width: u32, n_rows: u32, k: &[u64], out: DisjointSlice<u64>)`. Every `&[T]`/`DisjointSlice` is two launch params (ptr, len).

This task cannot be compiled on the author's machine (no nightly cuda-oxide toolchain, no CUDA 13). Write it, `cargo fmt --check` it with stable, and record the status honestly in `PTX_BUILD.md`.

- [ ] **Step 1: Crate files**

```toml
# circuits/gpu-kernels/Cargo.toml
[package]
name = "rand-zkvm-kernels"
version = "0.1.0"
edition = "2021"
publish = false

[[bin]]
name = "rand-zkvm-kernels"
path = "src/main.rs"

[dependencies]
cuda-device = { git = "https://github.com/NVlabs/cuda-oxide.git" }
```
```toml
# circuits/gpu-kernels/rust-toolchain.toml
[toolchain]
channel = "nightly-2026-08-28"
components = ["rust-src", "rustc-dev", "llvm-tools"]
```
```rust
// circuits/gpu-kernels/src/main.rs
//! cuda-oxide entry points for the Rand zkVM GPU prover. Every kernel is a thin wrapper
//! over the per-thread bodies in `rand-zkvm-cuda/src/device/kernels.rs`, shared by `#[path]`
//! so the CPU reference, the mock driver and the GPU execute identical code.
#[path = "../../rand-zkvm-cuda/src/device/gl.rs"] mod gl;
#[path = "../../rand-zkvm-cuda/src/device/poseidon2.rs"] mod poseidon2;
#[path = "../../rand-zkvm-cuda/src/device/kernels.rs"] mod kernels;
// `kernels.rs` says `use super::gl` / `use super::poseidon2`; with the modules mounted at the
// crate root those paths resolve because `main.rs` is their parent.

use cuda_device::{cuda_module, kernel, thread, DisjointSlice, SharedArray};

#[cuda_module]
mod k {
    use super::*;
    #[inline(always)]
    unsafe fn all<'a>(d: &'a mut DisjointSlice<u64>) -> &'a mut [u64] { core::slice::from_raw_parts_mut(d.as_mut_ptr(), d.len()) }

    #[kernel] pub fn scale_pow(mut data: DisjointSlice<u64>, n: u32, base: u64, uniform: u64) {
        let t = thread::index_1d().get(); let d = unsafe { all(&mut data) };
        kernels::scale_pow(t, d, n as usize, base, uniform);
    }
    #[kernel] pub fn bit_reverse(src: &[u64], mut dst: DisjointSlice<u64>, n: u32, log_n: u32) {
        let t = thread::index_1d().get(); let d = unsafe { all(&mut dst) };
        kernels::bit_reverse(t, src, d, n as usize, log_n as usize);
    }
    #[kernel] pub fn zero_extend(src: &[u64], mut dst: DisjointSlice<u64>, n: u32, n_ext: u32) {
        let t = thread::index_1d().get(); let d = unsafe { all(&mut dst) };
        kernels::zero_extend(t, src, d, n as usize, n_ext as usize);
    }
    #[kernel] pub fn to_col_major(src: &[u64], mut dst: DisjointSlice<u64>, rows: u32, cols: u32) {
        let t = thread::index_1d().get(); let d = unsafe { all(&mut dst) };
        kernels::to_col_major(t, src, d, rows as usize, cols as usize);
    }
    #[kernel] pub fn to_row_major(src: &[u64], mut dst: DisjointSlice<u64>, rows: u32, cols: u32) {
        let t = thread::index_1d().get(); let d = unsafe { all(&mut dst) };
        kernels::to_row_major(t, src, d, rows as usize, cols as usize);
    }
    #[kernel] pub fn dif_stage(mut data: DisjointSlice<u64>, n: u32, log_n: u32, s: u32, lo: &[u64], hi: &[u64]) {
        let t = thread::index_1d().get(); let d = unsafe { all(&mut data) };
        kernels::dif_stage(t, d, n as usize, log_n as usize, s as usize, lo, hi);
    }
    /// One block per 2^log_tile-element tile; blockDim.x = tile/2. Stages log_tile..=1 in shared memory.
    #[kernel] pub fn dif_tiles(mut data: DisjointSlice<u64>, n: u32, log_n: u32, log_tile: u32, lo: &[u64], hi: &[u64]) {
        static mut TILE: SharedArray<u64, 1024> = SharedArray::UNINIT;
        let tile = 1usize << log_tile;
        let base = thread::blockIdx_x() as usize * tile;
        let tx = thread::threadIdx_x() as usize;
        let d = unsafe { all(&mut data) };
        let _ = n;
        unsafe { TILE[tx] = d[base + tx]; TILE[tx + tile / 2] = d[base + tx + tile / 2]; }
        thread::sync_threads();
        let mut s = log_tile as usize;
        while s >= 1 {
            let tl = unsafe { core::slice::from_raw_parts_mut(TILE.as_mut_ptr(), tile) };
            kernels::dif_tile_stage(tx, tl, log_n as usize, s, lo, hi);
            thread::sync_threads();
            s -= 1;
        }
        unsafe { d[base + tx] = TILE[tx]; d[base + tx + tile / 2] = TILE[tx + tile / 2]; }
    }
    #[kernel] pub fn copy_columns(src: &[u64], src_w: u32, mut dst: DisjointSlice<u64>, dst_w: u32, col_off: u32) {
        let t = thread::index_1d().get(); let d = unsafe { all(&mut dst) };
        kernels::copy_columns(t, src, src_w as usize, d, dst_w as usize, col_off as usize);
    }
    #[kernel] pub fn poseidon2_rows(rows: &[u64], width: u32, n: u32, k: &[u64], mut out: DisjointSlice<u64>) {
        let t = thread::index_1d().get(); let o = unsafe { all(&mut out) };
        kernels::poseidon2_rows(t, rows, width as usize, n as usize, k, o);
    }
    #[kernel] pub fn poseidon2_compress(prev: &[u64], next_len: u32, k: &[u64], mut out: DisjointSlice<u64>) {
        let t = thread::index_1d().get(); let o = unsafe { all(&mut out) };
        kernels::poseidon2_compress(t, prev, next_len as usize, k, o);
    }
    #[kernel] pub fn poseidon2_inject(prev: &[u64], raw_next: u32, rows: &[u64], width: u32, n_rows: u32, k: &[u64], mut out: DisjointSlice<u64>) {
        let t = thread::index_1d().get(); let o = unsafe { all(&mut out) };
        kernels::poseidon2_inject(t, prev, raw_next as usize, rows, width as usize, n_rows as usize, k, o);
    }
}

fn main() {}
```
Note `dif_tiles` requires `log_tile ≥ 1`; the host never launches it for `n < 2` (a size-1 NTT is the identity and the host skips `dif` entirely when `n == 1`; add that early return to both engines' `dif`).

```make
# circuits/gpu-kernels/Justfile
# Requires: CUDA Toolkit 13, LLVM 21+, and `cargo +nightly-2026-08-28 install --git https://github.com/NVlabs/cuda-oxide.git cargo-oxide`
kernels arch="sm_80":
    cargo oxide build --arch {{arch}}
    cp rand-zkvm-kernels.ptx ../rand-zkvm-cuda/ptx/kernels.{{arch}}.ptx
    @echo "record the cuda-oxide commit and toolkit version in ../rand-zkvm-cuda/ptx/PTX_BUILD.md"
```

```markdown
# PTX_BUILD.md
Status: **no PTX has been built yet.** `gpu-kernels` has never been compiled: the author's
machines have no NVIDIA GPU and no CUDA 13 toolkit. `GpuProver::probe()` returns
`CudaError::MissingPtx` until `kernels.sm_80.ptx` exists here.

To build: on a Linux box with an R580+ driver, CUDA 13, LLVM 21 and the pinned nightly,
`cd circuits/gpu-kernels && just kernels sm_80`, then fill in:
- cuda-oxide commit: (unfilled)
- CUDA toolkit: (unfilled)
- built on: (unfilled)
and run `cargo test -p rand-zkvm-cuda --features cuda-hw`.
```

- [ ] **Step 2: `cargo fmt --check` under `circuits/gpu-kernels` with the stable toolchain (`cargo +1.98.1 fmt --check -- src/main.rs`); fix syntax only.**
- [ ] **Step 3: Commit** — `git commit -m "cuda: gpu-kernels cuda-oxide crate (unbuilt: no toolkit available), PTX_BUILD.md"`.

---

### Task 8: Driver surface, mock driver, `GpuProver`, `CudaError`

**Files:**
- Create: `src/gpu/mod.rs`, `src/gpu/driver/mod.rs`, `src/gpu/driver/real.rs`, `src/gpu/driver/mock.rs`
- Modify: `src/lib.rs` (`#[cfg(any(feature = "cuda", feature = "mock-driver"))] pub mod gpu;`)
- Test: `tests/gpu_driver.rs` (run with `--features mock-driver`)

**Interfaces:**
- Produces:
```rust
// src/gpu/mod.rs
#[derive(Debug, thiserror::Error)]
pub enum CudaError {
    #[error("CUDA driver: {0}")] Driver(String),
    #[error("CUDA context on device {ordinal}: {msg}")] Context { ordinal: usize, msg: String },
    #[error("no PTX for the GPU kernels at {0} (see rand-zkvm-cuda/ptx/PTX_BUILD.md)")] MissingPtx(std::path::PathBuf),
    #[error("loading PTX module: {0}")] PtxLoad(String),
    #[error("device allocation of {bytes} bytes failed ({free} bytes free); use a lower tier")] Alloc { bytes: usize, free: usize },
    #[error("kernel {kernel}: {msg}")] Launch { kernel: &'static str, msg: String },
    #[error("host/device copy: {0}")] Copy(String),
}
pub struct GpuProver { pub dev: driver::Device, pub module: driver::Module, pub tw_lo: driver::Buffer, pub tw_hi: driver::Buffer, pub tw_inv_lo: driver::Buffer, pub tw_inv_hi: driver::Buffer, pub consts: driver::Buffer, pub free_bytes: usize }
impl GpuProver {
    pub fn probe(perm_seed: u64) -> Result<Arc<Self>, CudaError>;        // device 0, PTX from `ptx_path()`
    pub fn ptx_path() -> PathBuf;  // $RAND_ZKVM_PTX if set, else <crate manifest>/ptx/kernels.sm_80.ptx
    pub fn launch(&self, name: &'static str, total_threads: usize, block: u32, args: &[driver::Arg<'_>]) -> Result<(), CudaError>;
}
// src/gpu/driver/mod.rs
pub enum Arg<'a> { Buf(&'a Buffer), U32(u32), U64(u64) }
pub struct Device(..); pub struct Module(..); pub struct Buffer(..);
impl Device {
    pub fn open(ordinal: usize) -> Result<Device, String>;
    pub fn free_bytes(&self) -> Result<usize, String>;
    pub fn load_ptx(&self, src: &str) -> Result<Module, String>;
    pub fn alloc(&self, len: usize) -> Result<Buffer, String>;          // zeroed u64s
    pub fn upload(&self, data: &[u64]) -> Result<Buffer, String>;
    pub fn download(&self, buf: &Buffer) -> Result<Vec<u64>, String>;
    pub fn launch(&self, m: &Module, name: &str, grid: u32, block: u32, args: &[Arg<'_>]) -> Result<(), String>;  // synchronous
}
impl Buffer { pub fn len(&self) -> usize; }
```
- Mock driver: `Device::open` succeeds; `load_ptx` accepts any text; `launch` runs `device::kernels` bodies for `t in 0..grid*block` (and the tile loop for `dif_tiles`), dispatching on `name`; unknown name → `Err`. `free_bytes` returns 1 GiB.

- [ ] **Step 1: Failing test**

```rust
// circuits/rand-zkvm-cuda/tests/gpu_driver.rs
#![cfg(feature = "mock-driver")]
use rand_zkvm_cuda::gpu::{driver::{Arg, Device}, CudaError, GpuProver};

#[test]
fn mock_launch_runs_kernel_bodies() {
    let d = Device::open(0).unwrap();
    let m = d.load_ptx("// mock").unwrap();
    let src = d.upload(&[1, 2, 3, 4, 5, 6, 7, 8]).unwrap(); // row-major 4×2
    let dst = d.alloc(8).unwrap();
    d.launch(&m, "to_col_major", 1, 256, &[Arg::Buf(&src), Arg::Buf(&dst), Arg::U32(4), Arg::U32(2)]).unwrap();
    assert_eq!(d.download(&dst).unwrap(), vec![1, 3, 5, 7, 2, 4, 6, 8]);
    assert!(d.launch(&m, "no_such_kernel", 1, 1, &[]).is_err());
}

#[test]
fn probe_reports_missing_ptx_when_file_absent() {
    std::env::set_var("RAND_ZKVM_PTX", "/nonexistent/kernels.ptx");
    match GpuProver::probe(1) { Err(CudaError::MissingPtx(p)) => assert!(p.ends_with("kernels.ptx")), other => panic!("{other:?}") }
}

#[test]
fn probe_succeeds_with_any_ptx_text_under_mock() {
    let dir = std::env::temp_dir().join("rand-zkvm-cuda-mock"); std::fs::create_dir_all(&dir).unwrap();
    let p = dir.join("k.ptx"); std::fs::write(&p, "// mock ptx").unwrap();
    std::env::set_var("RAND_ZKVM_PTX", &p);
    let g = GpuProver::probe(0x5261_6e64_5a4b).unwrap();
    assert_eq!(g.consts.len(), 86);
    assert_eq!(g.tw_lo.len(), 1 << 13);
}
```
(Tests that set the env var must not run in parallel with each other: add `#[serial]`-free ordering by putting them in one test function if flakiness appears.)

- [ ] **Step 2: Run `cargo test --features mock-driver --test gpu_driver`, expect failure.**

- [ ] **Step 3: Implement driver surface + mock**

```rust
// circuits/rand-zkvm-cuda/src/gpu/driver/mod.rs
#[cfg(all(feature = "cuda", not(feature = "mock-driver")))] mod real;
#[cfg(all(feature = "cuda", not(feature = "mock-driver")))] pub use real::{Buffer, Device, Module};
#[cfg(feature = "mock-driver")] mod mock;
#[cfg(feature = "mock-driver")] pub use mock::{Buffer, Device, Module};

pub enum Arg<'a> { Buf(&'a Buffer), U32(u32), U64(u64) }
```

```rust
// circuits/rand-zkvm-cuda/src/gpu/driver/mock.rs
//! Runs the shared kernel bodies on the host, sequentially, with the real launch geometry.
use std::cell::RefCell;
use super::Arg;
use crate::device::kernels as k;

pub struct Device;
pub struct Module;
pub struct Buffer(pub RefCell<Vec<u64>>);
impl Buffer { pub fn len(&self) -> usize { self.0.borrow().len() } }

fn buf<'a>(a: &'a Arg<'a>) -> &'a Buffer { match a { Arg::Buf(b) => b, _ => panic!("expected buffer arg") } }
fn u(a: &Arg<'_>) -> usize { match a { Arg::U32(x) => *x as usize, Arg::U64(x) => *x as usize, _ => panic!("expected scalar arg") } }
fn u64_(a: &Arg<'_>) -> u64 { match a { Arg::U64(x) => *x, Arg::U32(x) => *x as u64, _ => panic!("expected scalar arg") } }

impl Device {
    pub fn open(_ordinal: usize) -> Result<Device, String> { Ok(Device) }
    pub fn free_bytes(&self) -> Result<usize, String> { Ok(1 << 30) }
    pub fn load_ptx(&self, _src: &str) -> Result<Module, String> { Ok(Module) }
    pub fn alloc(&self, len: usize) -> Result<Buffer, String> { Ok(Buffer(RefCell::new(vec![0; len]))) }
    pub fn upload(&self, data: &[u64]) -> Result<Buffer, String> { Ok(Buffer(RefCell::new(data.to_vec()))) }
    pub fn download(&self, b: &Buffer) -> Result<Vec<u64>, String> { Ok(b.0.borrow().clone()) }
    pub fn launch(&self, _m: &Module, name: &str, grid: u32, block: u32, a: &[Arg<'_>]) -> Result<(), String> {
        let total = grid as usize * block as usize;
        match name {
            "scale_pow" => { let mut d = buf(&a[0]).0.borrow_mut(); for t in 0..total { k::scale_pow(t, &mut d, u(&a[1]), u64_(&a[2]), u64_(&a[3])); } }
            "bit_reverse" => { let s = buf(&a[0]).0.borrow(); let mut d = buf(&a[1]).0.borrow_mut(); for t in 0..total { k::bit_reverse(t, &s, &mut d, u(&a[2]), u(&a[3])); } }
            "zero_extend" => { let s = buf(&a[0]).0.borrow(); let mut d = buf(&a[1]).0.borrow_mut(); for t in 0..total { k::zero_extend(t, &s, &mut d, u(&a[2]), u(&a[3])); } }
            "to_col_major" => { let s = buf(&a[0]).0.borrow(); let mut d = buf(&a[1]).0.borrow_mut(); for t in 0..total { k::to_col_major(t, &s, &mut d, u(&a[2]), u(&a[3])); } }
            "to_row_major" => { let s = buf(&a[0]).0.borrow(); let mut d = buf(&a[1]).0.borrow_mut(); for t in 0..total { k::to_row_major(t, &s, &mut d, u(&a[2]), u(&a[3])); } }
            "dif_stage" => { let mut d = buf(&a[0]).0.borrow_mut(); let lo = buf(&a[4]).0.borrow(); let hi = buf(&a[5]).0.borrow(); for t in 0..total { k::dif_stage(t, &mut d, u(&a[1]), u(&a[2]), u(&a[3]), &lo, &hi); } }
            "dif_tiles" => {
                let mut d = buf(&a[0]).0.borrow_mut(); let log_n = u(&a[2]); let log_tile = u(&a[3]); let lo = buf(&a[4]).0.borrow(); let hi = buf(&a[5]).0.borrow();
                let tile = 1usize << log_tile;
                for b in 0..grid as usize {
                    let chunk = &mut d[b * tile..(b + 1) * tile];
                    for s in (1..=log_tile).rev() { for t in 0..block as usize { k::dif_tile_stage(t, chunk, log_n, s, &lo, &hi); } }
                }
            }
            "copy_columns" => { let s = buf(&a[0]).0.borrow(); let mut d = buf(&a[2]).0.borrow_mut(); for t in 0..total { k::copy_columns(t, &s, u(&a[1]), &mut d, u(&a[3]), u(&a[4])); } }
            "poseidon2_rows" => { let r = buf(&a[0]).0.borrow(); let kk = buf(&a[3]).0.borrow(); let mut o = buf(&a[4]).0.borrow_mut(); for t in 0..total { k::poseidon2_rows(t, &r, u(&a[1]), u(&a[2]), &kk, &mut o); } }
            "poseidon2_compress" => { let p = buf(&a[0]).0.borrow(); let kk = buf(&a[2]).0.borrow(); let mut o = buf(&a[3]).0.borrow_mut(); for t in 0..total { k::poseidon2_compress(t, &p, u(&a[1]), &kk, &mut o); } }
            "poseidon2_inject" => { let p = buf(&a[0]).0.borrow(); let r = buf(&a[2]).0.borrow(); let kk = buf(&a[5]).0.borrow(); let mut o = buf(&a[6]).0.borrow_mut(); for t in 0..total { k::poseidon2_inject(t, &p, u(&a[1]), &r, u(&a[3]), u(&a[4]), &kk, &mut o); } }
            other => return Err(format!("unknown kernel {other}")),
        }
        Ok(())
    }
}
```
`RefCell` makes `Buffer: !Sync`; the engines hold buffers only transiently inside one call, and `GpuProver` fields are only read. If `Send + Sync` bounds bite (the engine traits require `Send + Sync`), wrap the mock buffer in `std::sync::Mutex<Vec<u64>>` instead of `RefCell` — same code with `.lock().unwrap()`.

- [ ] **Step 4: Real driver (compiles only with the toolkit; keep it minimal and obviously correct)**

```rust
// circuits/rand-zkvm-cuda/src/gpu/driver/real.rs
use std::ffi::c_void;
use std::sync::Arc;
use cuda_core::{CudaContext, CudaModule, CudaStream, DeviceBuffer};
use super::Arg;

pub struct Device { ctx: Arc<CudaContext>, stream: Arc<CudaStream> }
pub struct Module(Arc<CudaModule>);
pub struct Buffer(DeviceBuffer<u64>);
impl Buffer { pub fn len(&self) -> usize { self.0.len() } }

impl Device {
    pub fn open(ordinal: usize) -> Result<Device, String> {
        let ctx = CudaContext::new(ordinal).map_err(|e| e.to_string())?;
        let stream = ctx.default_stream();
        Ok(Device { ctx, stream })
    }
    pub fn free_bytes(&self) -> Result<usize, String> {
        let (mut free, mut total) = (0usize, 0usize);
        let r = unsafe { cuda_core::sys::cuMemGetInfo_v2(&mut free as *mut _, &mut total as *mut _) };
        if r == cuda_core::sys::cudaError_enum_CUDA_SUCCESS { Ok(free) } else { Err(format!("cuMemGetInfo: {r:?}")) }
    }
    pub fn load_ptx(&self, src: &str) -> Result<Module, String> { self.ctx.load_module_from_ptx_src(src).map(Module).map_err(|e| e.to_string()) }
    pub fn alloc(&self, len: usize) -> Result<Buffer, String> { DeviceBuffer::<u64>::zeroed(&self.stream, len).map(Buffer).map_err(|e| e.to_string()) }
    pub fn upload(&self, data: &[u64]) -> Result<Buffer, String> { DeviceBuffer::from_host(&self.stream, data).map(Buffer).map_err(|e| e.to_string()) }
    pub fn download(&self, b: &Buffer) -> Result<Vec<u64>, String> { b.0.to_host_vec(&self.stream).map_err(|e| e.to_string()) }
    pub fn launch(&self, m: &Module, name: &str, grid: u32, block: u32, args: &[Arg<'_>]) -> Result<(), String> {
        let f = m.0.load_function(name).map_err(|e| e.to_string())?;
        // Each `&[T]`/DisjointSlice kernel parameter is (ptr, len); scalars are one param each.
        let mut ptrs: Vec<u64> = Vec::new(); let mut lens: Vec<usize> = Vec::new(); let mut u32s: Vec<u32> = Vec::new(); let mut u64s: Vec<u64> = Vec::new();
        for a in args { match a { Arg::Buf(b) => { ptrs.push(b.0.cu_deviceptr() as u64); lens.push(b.0.len()); } Arg::U32(x) => u32s.push(*x), Arg::U64(x) => u64s.push(*x) } }
        let (mut ip, mut il, mut i32_, mut i64_) = (0, 0, 0, 0);
        let mut params: Vec<*mut c_void> = Vec::new();
        for a in args { match a {
            Arg::Buf(_) => { params.push(&mut ptrs[ip] as *mut u64 as *mut c_void); params.push(&mut lens[il] as *mut usize as *mut c_void); ip += 1; il += 1; }
            Arg::U32(_) => { params.push(&mut u32s[i32_] as *mut u32 as *mut c_void); i32_ += 1; }
            Arg::U64(_) => { params.push(&mut u64s[i64_] as *mut u64 as *mut c_void); i64_ += 1; }
        } }
        unsafe { cuda_core::simt::launch_kernel_on_stream(&f, (grid, 1, 1), (block, 1, 1), 0, &self.stream, &mut params) }.map_err(|e| e.to_string())?;
        self.stream.synchronize().map_err(|e| e.to_string())
    }
}
```
(Taking `&mut` into the vectors while iterating is fine because the vectors are fully built before pointers are taken; if the borrow checker objects, collect raw pointers with `as_mut_ptr().add(i)`.)

- [ ] **Step 5: `GpuProver`**

```rust
// circuits/rand-zkvm-cuda/src/gpu/mod.rs
pub mod driver;
pub mod ntt;
pub mod hash;
use std::path::PathBuf;
use std::sync::Arc;
use driver::{Arg, Buffer, Device, Module};

#[derive(Debug, thiserror::Error)]
pub enum CudaError { /* as in Interfaces */ }

pub struct GpuProver { pub dev: Device, pub module: Module, pub tw_lo: Buffer, pub tw_hi: Buffer, pub tw_inv_lo: Buffer, pub tw_inv_hi: Buffer, pub consts: Buffer, pub free_bytes: usize }

impl GpuProver {
    pub fn ptx_path() -> PathBuf {
        std::env::var_os("RAND_ZKVM_PTX").map(PathBuf::from).unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("ptx/kernels.sm_80.ptx"))
    }
    pub fn probe(perm_seed: u64) -> Result<Arc<Self>, CudaError> {
        let dev = Device::open(0).map_err(|msg| CudaError::Context { ordinal: 0, msg })?;
        let path = Self::ptx_path();
        let src = std::fs::read_to_string(&path).map_err(|_| CudaError::MissingPtx(path.clone()))?;
        let module = dev.load_ptx(&src).map_err(CudaError::PtxLoad)?;
        let free_bytes = dev.free_bytes().map_err(CudaError::Driver)?;
        let tw = crate::ntt::twiddles();
        let up = |v: &[u64]| dev.upload(v).map_err(CudaError::Copy);
        Ok(Arc::new(Self { tw_lo: up(&tw.lo)?, tw_hi: up(&tw.hi)?, tw_inv_lo: up(&tw.inv_lo)?, tw_inv_hi: up(&tw.inv_hi)?,
            consts: up(&crate::constants::poseidon2_constants(perm_seed))?, free_bytes, dev, module }))
    }
    pub fn launch(&self, name: &'static str, total_threads: usize, block: u32, args: &[Arg<'_>]) -> Result<(), CudaError> {
        if total_threads == 0 { return Ok(()); }
        let grid = (total_threads as u64).div_ceil(block as u64) as u32;
        self.dev.launch(&self.module, name, grid, block, args).map_err(|msg| CudaError::Launch { kernel: name, msg })
    }
    pub fn alloc(&self, len: usize) -> Result<Buffer, CudaError> {
        self.dev.alloc(len).map_err(|_| CudaError::Alloc { bytes: len * 8, free: self.dev.free_bytes().unwrap_or(0) })
    }
}
```
Create empty `gpu/ntt.rs` and `gpu/hash.rs` for now.

- [ ] **Step 6: Run `cargo test --features mock-driver --test gpu_driver`; also `cargo check` (no features) and `cargo test` (all earlier suites) still pass.**
- [ ] **Step 7: Commit** — `git commit -m "cuda: driver surface with cuda-core and mock implementations, GpuProver probe and CudaError"`.

---

### Task 9: `CudaNttEngine` and `CudaHashEngine`, verified through the mock driver

**Files:**
- Create: `src/gpu/ntt.rs`, `src/gpu/hash.rs`
- Test: `tests/gpu_engines.rs` (`--features mock-driver`)

**Interfaces:**
- Produces: `gpu::ntt::CudaNttEngine { gpu: Arc<GpuProver> }` (`NttEngine`, `Buf = driver::Buffer`; `Default` = `GpuProver::probe(DEFAULT_PERM_SEED).expect(..)` where `pub const DEFAULT_PERM_SEED: u64 = 0x5261_6e64_5a4b`), `gpu::hash::CudaHashEngine { gpu: Arc<GpuProver> }` (`HashEngine`, `Mat = Buffer`, `Dig = Buffer`). Both `Clone`.

- [ ] **Step 1: Failing test**

```rust
// circuits/rand-zkvm-cuda/tests/gpu_engines.rs
#![cfg(feature = "mock-driver")]
use std::sync::Arc;
use p3_commit::Mmcs;
use p3_dft::TwoAdicSubgroupDft;
use p3_field::{Field, PrimeCharacteristicRing};
use p3_goldilocks::Goldilocks;
use p3_matrix::Matrix;
use p3_matrix::dense::RowMajorMatrix;
use rand::{Rng, SeedableRng, rngs::StdRng};
use rand_zkvm_cuda::dft::Dft;
use rand_zkvm_cuda::gpu::{hash::CudaHashEngine, ntt::CudaNttEngine, GpuProver};
use rand_zkvm_cuda::merkle::{cpu::CpuHashEngine, mmcs::HidingMmcs};
use rand_zkvm_cuda::ntt::cpu::CpuNttEngine;

const SEED: u64 = 0x5261_6e64_5a4b;
fn gpu() -> Arc<GpuProver> {
    let dir = std::env::temp_dir().join("rand-zkvm-cuda-mock"); std::fs::create_dir_all(&dir).unwrap();
    let p = dir.join("k.ptx"); std::fs::write(&p, "// mock").unwrap(); std::env::set_var("RAND_ZKVM_PTX", &p);
    GpuProver::probe(SEED).unwrap()
}
fn mat(rng: &mut StdRng, n: usize, w: usize) -> RowMajorMatrix<Goldilocks> { RowMajorMatrix::new((0..n * w).map(|_| Goldilocks::from_u64(rng.random::<u64>() % 0xFFFF_FFFF_0000_0001)).collect(), w) }

#[test]
fn cuda_dft_equals_cpu_dft_under_mock() {
    let g = gpu();
    let cuda = Dft(Arc::new(CudaNttEngine { gpu: g }));
    let cpu = Dft::<CpuNttEngine>::default();
    let mut rng = StdRng::seed_from_u64(41);
    for log_n in [1usize, 4, 10, 11, 13] { for w in [1usize, 6] {
        let m = mat(&mut rng, 1 << log_n, w);
        assert_eq!(cuda.coset_lde_batch(m.clone(), 3, Goldilocks::GENERATOR).to_row_major_matrix(), cpu.coset_lde_batch(m.clone(), 3, Goldilocks::GENERATOR).to_row_major_matrix());
        assert_eq!(cuda.coset_idft_batch(m.clone(), Goldilocks::GENERATOR), cpu.coset_idft_batch(m, Goldilocks::GENERATOR));
    } }
}

#[test]
fn cuda_mmcs_equals_cpu_mmcs_under_mock() {
    let g = gpu();
    let cuda = HidingMmcs::new(Arc::new(CudaHashEngine { gpu: g }), SEED, 2, StdRng::seed_from_u64(9));
    let cpu = HidingMmcs::new(Arc::new(CpuHashEngine::new(SEED)), SEED, 2, StdRng::seed_from_u64(9));
    let mut rng = StdRng::seed_from_u64(42);
    let ms: Vec<_> = [(1usize << 10, 56), (1 << 11, 20), (1 << 12, 12), (1 << 6, 3), (1 << 12, 1)].iter().map(|&(h, w)| mat(&mut rng, h, w)).collect();
    let (c1, pd1) = cuda.commit(ms.clone());
    let (c2, pd2) = cpu.commit(ms);
    assert_eq!(c1, c2);
    let idx: Vec<usize> = (0..50).map(|_| rng.random::<u64>() as usize % (1 << 12)).collect();
    let a = cuda.open_multi_batch(&idx, &pd1); let b = cpu.open_multi_batch(&idx, &pd2);
    assert_eq!(postcard::to_allocvec(&a).unwrap(), postcard::to_allocvec(&b).unwrap());
}
```

- [ ] **Step 2: Run, expect failure.**

- [ ] **Step 3: Implement the NTT engine**

```rust
// circuits/rand-zkvm-cuda/src/gpu/ntt.rs
use std::sync::Arc;
use p3_util::log2_strict_usize;
use super::driver::{Arg, Buffer};
use super::GpuProver;
use crate::ntt::{NttEngine, LOG_TILE};

pub const DEFAULT_PERM_SEED: u64 = 0x5261_6e64_5a4b;
const BLOCK: u32 = 256;

#[derive(Clone)]
pub struct CudaNttEngine { pub gpu: Arc<GpuProver> }
impl Default for CudaNttEngine { fn default() -> Self { Self { gpu: GpuProver::probe(DEFAULT_PERM_SEED).unwrap_or_else(|e| panic!("{e}")) } } }

impl CudaNttEngine {
    fn ok<T>(r: Result<T, super::CudaError>) -> T { r.unwrap_or_else(|e| panic!("{e}")) }
}

impl NttEngine for CudaNttEngine {
    type Buf = Buffer;
    fn max_columns(&self, n: usize) -> usize {
        // LDE keeps ~4 buffers of n×wc u64 alive; leave headroom.
        ((self.gpu.free_bytes / 2) / (n * 8 * 4)).max(1)
    }
    fn upload_row_major(&self, values: &[u64], n: usize, w: usize) -> Buffer {
        let src = Self::ok(self.gpu.dev.upload(values).map_err(super::CudaError::Copy));
        let dst = Self::ok(self.gpu.alloc(n * w));
        Self::ok(self.gpu.launch("to_col_major", n * w, BLOCK, &[Arg::Buf(&src), Arg::Buf(&dst), Arg::U32(n as u32), Arg::U32(w as u32)]));
        dst
    }
    fn download_row_major(&self, buf: &Buffer, n: usize, w: usize) -> Vec<u64> {
        let dst = Self::ok(self.gpu.alloc(n * w));
        Self::ok(self.gpu.launch("to_row_major", n * w, BLOCK, &[Arg::Buf(buf), Arg::Buf(&dst), Arg::U32(n as u32), Arg::U32(w as u32)]));
        Self::ok(self.gpu.dev.download(&dst).map_err(super::CudaError::Copy))
    }
    fn dif(&self, buf: &mut Buffer, n: usize, w: usize, inverse: bool) {
        if n < 2 { return; }
        let log_n = log2_strict_usize(n);
        let (lo, hi) = if inverse { (&self.gpu.tw_inv_lo, &self.gpu.tw_inv_hi) } else { (&self.gpu.tw_lo, &self.gpu.tw_hi) };
        let log_tile = LOG_TILE.min(log_n);
        for s in ((log_tile + 1)..=log_n).rev() {
            Self::ok(self.gpu.launch("dif_stage", w * n / 2, BLOCK, &[Arg::Buf(buf), Arg::U32(n as u32), Arg::U32(log_n as u32), Arg::U32(s as u32), Arg::Buf(lo), Arg::Buf(hi)]));
        }
        let tile = 1usize << log_tile;
        let blocks = w * n / tile;
        Self::ok(self.gpu.launch("dif_tiles", blocks * (tile / 2), (tile / 2) as u32, &[Arg::Buf(buf), Arg::U32(n as u32), Arg::U32(log_n as u32), Arg::U32(log_tile as u32), Arg::Buf(lo), Arg::Buf(hi)]));
    }
    fn bit_reverse(&self, buf: &Buffer, n: usize, w: usize) -> Buffer {
        let dst = Self::ok(self.gpu.alloc(n * w));
        Self::ok(self.gpu.launch("bit_reverse", n * w, BLOCK, &[Arg::Buf(buf), Arg::Buf(&dst), Arg::U32(n as u32), Arg::U32(log2_strict_usize(n) as u32)]));
        dst
    }
    fn scale_pow(&self, buf: &mut Buffer, n: usize, w: usize, base: u64, uniform: u64) {
        Self::ok(self.gpu.launch("scale_pow", n * w, BLOCK, &[Arg::Buf(buf), Arg::U32(n as u32), Arg::U64(base), Arg::U64(uniform)]));
    }
    fn zero_extend(&self, buf: &Buffer, n: usize, w: usize, added_bits: usize) -> Buffer {
        let n_ext = n << added_bits;
        let dst = Self::ok(self.gpu.alloc(n_ext * w));
        Self::ok(self.gpu.launch("zero_extend", n_ext * w, BLOCK, &[Arg::Buf(buf), Arg::Buf(&dst), Arg::U32(n as u32), Arg::U32(n_ext as u32)]));
        dst
    }
}
```
`launch` computes `grid = ceil(total/block)`; for `dif_tiles` `total = blocks·(tile/2)` and `block = tile/2` so `grid = blocks` exactly. The mock's `dif_tiles` branch relies on this.

- [ ] **Step 4: Implement the hash engine**

```rust
// circuits/rand-zkvm-cuda/src/gpu/hash.rs
use std::sync::Arc;
use super::driver::{Arg, Buffer};
use super::GpuProver;
use crate::merkle::{Digest, HashEngine};

const BLOCK: u32 = 256;

#[derive(Clone)]
pub struct CudaHashEngine { pub gpu: Arc<GpuProver> }
impl CudaHashEngine { fn ok<T>(r: Result<T, super::CudaError>) -> T { r.unwrap_or_else(|e| panic!("{e}")) } }

impl HashEngine for CudaHashEngine {
    type Mat = Buffer; type Dig = Buffer;
    fn upload(&self, values: &[u64], _width: usize) -> Buffer { Self::ok(self.gpu.dev.upload(values).map_err(super::CudaError::Copy)) }
    fn concat(&self, parts: &[(&Buffer, usize)], n: usize) -> (Buffer, usize) {
        let total: usize = parts.iter().map(|p| p.1).sum();
        let dst = Self::ok(self.gpu.alloc(n * total));
        let mut off = 0;
        for (src, w) in parts {
            Self::ok(self.gpu.launch("copy_columns", n * w, BLOCK, &[Arg::Buf(src), Arg::U32(*w as u32), Arg::Buf(&dst), Arg::U32(total as u32), Arg::U32(off as u32)]));
            off += w;
        }
        (dst, total)
    }
    fn hash_rows(&self, rows: &Buffer, width: usize, n: usize, out_len: usize) -> Buffer {
        let out = Self::ok(self.gpu.alloc(4 * out_len));
        Self::ok(self.gpu.launch("poseidon2_rows", n, BLOCK, &[Arg::Buf(rows), Arg::U32(width as u32), Arg::U32(n as u32), Arg::Buf(&self.gpu.consts), Arg::Buf(&out)]));
        out
    }
    fn compress(&self, prev: &Buffer, next_len: usize, out_len: usize) -> Buffer {
        let out = Self::ok(self.gpu.alloc(4 * out_len));
        Self::ok(self.gpu.launch("poseidon2_compress", next_len, BLOCK, &[Arg::Buf(prev), Arg::U32(next_len as u32), Arg::Buf(&self.gpu.consts), Arg::Buf(&out)]));
        out
    }
    fn inject(&self, prev: &Buffer, raw_next: usize, rows: &Buffer, width: usize, n_rows: usize, out_len: usize) -> Buffer {
        let out = Self::ok(self.gpu.alloc(4 * out_len));
        Self::ok(self.gpu.launch("poseidon2_inject", raw_next, BLOCK, &[Arg::Buf(prev), Arg::U32(raw_next as u32), Arg::Buf(rows), Arg::U32(width as u32), Arg::U32(n_rows as u32), Arg::Buf(&self.gpu.consts), Arg::Buf(&out)]));
        out
    }
    fn download(&self, dig: &Buffer) -> Vec<Digest> {
        Self::ok(self.gpu.dev.download(dig).map_err(super::CudaError::Copy)).chunks_exact(4).map(|c| [c[0], c[1], c[2], c[3]]).collect()
    }
}
```
In `concat`, when `parts.len() == 1` still copy (a fresh buffer is simplest); an optimisation can return the same buffer later.

- [ ] **Step 5: Run `cargo test --features mock-driver`, all suites pass; `cargo check --features cuda` is expected to fail here only for lack of the CUDA toolkit (cuda-bindings build script) — record that in the commit message, not as a test failure.**
- [ ] **Step 6: Commit** — `git commit -m "cuda: CudaNttEngine and CudaHashEngine; identical to CPU engines under the mock driver"`.

---

### Task 10: `research` backends — `Backend`, `prove_with`, reference and CUDA configs

**Files:**
- Modify: `circuits/research/Cargo.toml` (deps + features), `circuits/research/src/machine.rs`
- Test: `circuits/research/tests/backend.rs`

**Interfaces:**
- Consumes: `rand_zkvm_cuda::{dft::Dft, merkle::mmcs::HidingMmcs, ntt::cpu::CpuNttEngine, merkle::cpu::CpuHashEngine, gpu::{GpuProver, ntt::CudaNttEngine, hash::CudaHashEngine}}`.
- Produces in `machine.rs`:
```rust
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Backend { Cpu, #[cfg(feature = "reference-backend")] Reference, #[cfg(feature = "cuda")] Cuda }
pub enum ProveError { Exec(ExecError), NoTier(usize), TooManyCycles { cycles: usize, tier: Tier }, Backend(String) }
impl Machine { pub fn prove_with(&self, backend: Backend, program: &Program, inputs: &[u32], tier: Option<Tier>) -> Result<(Proof, Execution), ProveError>; }
```

- [ ] **Step 1: Cargo wiring**

Add to `circuits/research/Cargo.toml`:
```toml
rand-zkvm-cuda = { path = "../rand-zkvm-cuda", optional = true }

[features]
default = []
reference-backend = ["dep:rand-zkvm-cuda"]
mock-cuda = ["cuda", "rand-zkvm-cuda/mock-driver"]
cuda = ["dep:rand-zkvm-cuda", "rand-zkvm-cuda/cuda"]
```
(`mock-cuda` lets the whole `Backend::Cuda` path run here on the mock driver.)

- [ ] **Step 2: Failing test**

```rust
// circuits/research/tests/backend.rs
#![cfg(any(feature = "reference-backend", feature = "mock-cuda"))]
use rand_zkvm::emulator::execute;
use rand_zkvm::guests;
use rand_zkvm::machine::{Backend, FriProfile, Machine};

fn backend() -> Backend {
    #[cfg(feature = "mock-cuda")] {
        let dir = std::env::temp_dir().join("rand-zkvm-cuda-mock"); std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("k.ptx"); std::fs::write(&p, "// mock").unwrap(); std::env::set_var("RAND_ZKVM_PTX", &p);
        return Backend::Cuda;
    }
    #[allow(unreachable_code)] Backend::Reference
}

#[test]
fn every_guest_proves_on_the_backend_and_verifies_on_the_cpu() {
    let m = Machine::new(FriProfile::Test);
    for (name, program, inputs) in guests::all() {
        let (proof, exec) = m.prove_with(backend(), &program, &inputs, None).unwrap_or_else(|e| panic!("{name}: {e:?}"));
        let expected = execute(&program, &inputs, 1 << 20).unwrap();
        assert_eq!(exec.outputs, expected.outputs, "{name}");
        m.verify(&program, &proof).unwrap_or_else(|e| panic!("{name}: verify {e:?}"));
        let bytes = proof.to_bytes();
        m.verify(&program, &rand_zkvm::machine::Proof::from_bytes(&bytes).unwrap()).unwrap();
    }
}

#[test]
fn backend_proof_has_the_same_shape_as_a_cpu_proof() {
    let m = Machine::new(FriProfile::Test);
    let p = guests::fib(10);
    let (a, _) = m.prove_with(backend(), &p, &[], None).unwrap();
    let (b, _) = m.prove(&p, &[], None).unwrap();
    assert_eq!(a.tier, b.tier);
    assert_eq!(a.public_values, b.public_values);
    assert_eq!(a.batch.degree_bits, b.batch.degree_bits);
    // sizes agree to within the FRI query randomness
    assert!((a.size() as i64 - b.size() as i64).abs() < 4096, "{} vs {}", a.size(), b.size());
}
```
(Check `Proof::from_bytes` exists in `machine.rs`; the fullnode codec uses it. If it is named differently, use that name.)

- [ ] **Step 3: Implement in `machine.rs`**

Add after the existing `Config` aliases:
```rust
#[cfg(feature = "reference-backend")]
mod reference_cfg {
    use super::*;
    pub type Mmcs = rand_zkvm_cuda::merkle::mmcs::HidingMmcs<rand_zkvm_cuda::merkle::cpu::CpuHashEngine>;
    pub type Dft = rand_zkvm_cuda::dft::Dft<rand_zkvm_cuda::ntt::cpu::CpuNttEngine>;
    pub type Pcs = HidingFriPcs<Val, Dft, Mmcs, ExtensionMmcs<Val, Challenge, Mmcs>, StdRng>;
    pub type Config = StarkConfig<Pcs, Challenge, Challenger>;
    pub fn config(profile: FriProfile, mmcs_rng: StdRng, pcs_rng: StdRng) -> Config {
        let engine = std::sync::Arc::new(rand_zkvm_cuda::merkle::cpu::CpuHashEngine::new(PERM_SEED));
        let mmcs = Mmcs::new(engine, PERM_SEED, 2, mmcs_rng);
        super::generic_config(profile, Dft::default(), mmcs, pcs_rng)
    }
}
#[cfg(feature = "cuda")]
mod cuda_cfg {
    use super::*;
    pub type Mmcs = rand_zkvm_cuda::merkle::mmcs::HidingMmcs<rand_zkvm_cuda::gpu::hash::CudaHashEngine>;
    pub type Dft = rand_zkvm_cuda::dft::Dft<rand_zkvm_cuda::gpu::ntt::CudaNttEngine>;
    pub type Pcs = HidingFriPcs<Val, Dft, Mmcs, ExtensionMmcs<Val, Challenge, Mmcs>, StdRng>;
    pub type Config = StarkConfig<Pcs, Challenge, Challenger>;
    pub fn config(profile: FriProfile, gpu: std::sync::Arc<rand_zkvm_cuda::gpu::GpuProver>, mmcs_rng: StdRng, pcs_rng: StdRng) -> Config {
        let engine = std::sync::Arc::new(rand_zkvm_cuda::gpu::hash::CudaHashEngine { gpu: gpu.clone() });
        let mmcs = Mmcs::new(engine, PERM_SEED, 2, mmcs_rng);
        let dft = Dft(std::sync::Arc::new(rand_zkvm_cuda::gpu::ntt::CudaNttEngine { gpu }));
        super::generic_config(profile, dft, mmcs, pcs_rng)
    }
}
```
Refactor `build_config` so the FRI parameters live in one generic helper both paths share (keep `build_config`'s behaviour identical):
```rust
fn generic_config<D, M>(profile: FriProfile, dft: D, val_mmcs: M, pcs_rng: StdRng) -> StarkConfig<HidingFriPcs<Val, D, M, ExtensionMmcs<Val, Challenge, M>, StdRng>, Challenge, Challenger>
where D: p3_dft::TwoAdicSubgroupDft<Val>, M: p3_commit::Mmcs<Val, MultiProof: Sync, Error: Sync> + Clone,
{
    let challenge_mmcs = ExtensionMmcs::new(val_mmcs.clone());
    let fri = FriParameters { log_blowup: 3, log_final_poly_len: 0, num_queries: profile.num_queries(), commit_proof_of_work_bits: 0, query_proof_of_work_bits: profile.pow_bits(), mmcs: challenge_mmcs };
    let pcs = HidingFriPcs::new(dft, val_mmcs, fri, 4, pcs_rng);
    StarkConfig::new(pcs, Challenger::new(permutation()))
}
```
(Copy the exact `FriParameters` fields and the `StarkConfig::new`/challenger construction from the current `build_config`; the values above are what it uses today — verify against the file before editing. `build_config` becomes `generic_config(profile, Dft::default(), ValMmcs::new(hash, compress, 2, mmcs_rng), pcs_rng)`.)

Then the backend API:
```rust
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Backend { Cpu, #[cfg(feature = "reference-backend")] Reference, #[cfg(feature = "cuda")] Cuda }

impl Machine {
    pub fn prove_with(&self, backend: Backend, program: &Program, inputs: &[u32], tier: Option<Tier>) -> Result<(Proof, Execution), ProveError> {
        match backend {
            Backend::Cpu => self.prove(program, inputs, tier),
            #[cfg(feature = "reference-backend")]
            Backend::Reference => {
                let cfg = reference_cfg::config(self.profile, StdRng::from_rng(&mut rand::rng()), StdRng::from_rng(&mut rand::rng()));
                let key = reference_cfg::config(self.profile, key_rngs(program).0, key_rngs(program).1);
                self.prove_on(&cfg, &key, program, inputs, tier)
            }
            #[cfg(feature = "cuda")]
            Backend::Cuda => {
                let gpu = rand_zkvm_cuda::gpu::GpuProver::probe(PERM_SEED).map_err(|e| ProveError::Backend(e.to_string()))?;
                let cfg = cuda_cfg::config(self.profile, gpu.clone(), StdRng::from_rng(&mut rand::rng()), StdRng::from_rng(&mut rand::rng()));
                let key = cuda_cfg::config(self.profile, gpu, key_rngs(program).0, key_rngs(program).1);
                self.prove_on(&cfg, &key, program, inputs, tier)
            }
        }
    }

    /// Generic body of `prove_traces` over any structurally compatible config. The proof is
    /// converted to the CPU `Config` by a serialisation round trip (identical wire format).
    fn prove_on<SC>(&self, cfg: &SC, key_cfg: &SC, program: &Program, inputs: &[u32], tier: Option<Tier>) -> Result<(Proof, Execution), ProveError>
    where SC: p3_uni_stark::StarkGenericConfig<Challenge = Challenge, Challenger = Challenger> + /* the bounds prove_batch needs; copy from prove_batch's signature */,
    {
        let exec = execute(program, inputs, 1 << 20).map_err(ProveError::Exec)?;
        let tier = match tier { Some(t) => t, None => Tier::for_cycles(exec.cycles()).ok_or(ProveError::NoTier(exec.cycles()))? };
        let traces = build_traces(program, &exec, tier)?;
        let airs = chips(program);
        let mats = traces.as_slice();
        let instances: Vec<StarkInstance<'_, SC, Chip>> = airs.iter().zip(mats.iter()).enumerate().map(|(i, (air, trace))| StarkInstance { air, trace, public_values: if i == 1 { traces.public_values.clone() } else { vec![] } }).collect();
        let prover_data = ProverData::from_airs_and_degrees(key_cfg, &airs, &self.log_ext_degrees(program, tier));
        // The preprocessed commitment is what the verifier recomputes on the CPU; the backend
        // must reproduce it exactly or verification fails at the first check.
        let batch = prove_batch(cfg, &instances, &prover_data);
        let bytes = postcard::to_allocvec(&batch).map_err(|e| ProveError::Backend(format!("proof serialise: {e}")))?;
        let batch: BatchProof<Config> = postcard::from_bytes(&bytes).map_err(|e| ProveError::Backend(format!("proof convert: {e}")))?;
        Ok((Proof { tier, public_values: traces.public_values.iter().map(|x| x.as_canonical_u64()).collect(), batch }, exec))
    }
}

/// The deterministic RNG pair `key_config` uses, so backends build byte-identical preprocessed commitments.
fn key_rngs(program: &Program) -> (StdRng, StdRng) { /* extract from the existing key_config: the two seeds derived from program_digest */ }
```
Refactor `key_config` to call `key_rngs` so both paths share the seed derivation. Also add `Backend(String)` to `ProveError`. `prove_traces` may be re-expressed as `prove_on(&self.config, &key_config(..), ..)` once the generic bounds compile; if the trait bounds on `prove_on` are painful, duplicate the body per backend (two `#[cfg]` blocks) rather than fight them — correctness first.

- [ ] **Step 4: Run**
`cargo test --features reference-backend --test backend` and `cargo test --features mock-cuda --test backend` → pass. `cargo test` (no features) still passes (the 43 existing tests).
- [ ] **Step 5: Commit** — `git commit -m "research: Backend {Cpu, Reference, Cuda} and Machine::prove_with; reference and mock-CUDA proofs verify on the CPU"`.

---

### Task 11: Fullnode `--cuda` flag, executor backend, sync script

**Files:**
- Modify: `fullnode/crates/shrugg-zkvm/Cargo.toml`, `fullnode/crates/shrugg-zkvm/src/executor.rs`, `fullnode/crates/shrugg-client/Cargo.toml`, `fullnode/crates/shrugg-client/src/main.rs`, `fullnode/deploy/sync-zkvm.sh`, `fullnode/docs/confidential.md`
- Test: `fullnode/crates/shrugg-zkvm/tests/executor.rs` (add one test), `fullnode/crates/shrugg-client` build check with and without the feature

**Interfaces:**
- `executor::prove(profile, program, inputs, tier, backend: Backend)`; `Backend` re-exported from `shrugg_zkvm::machine`.
- CLI: `shrugg call ... --cuda`.

- [ ] **Step 1: Sync the research crate** — run `deploy/sync-zkvm.sh` (it copies `machine.rs` with the new backend code and `generic_config`); confirm `git diff --stat` touches only `crates/shrugg-zkvm/src/machine.rs` plus tests. Add to `crates/shrugg-zkvm/Cargo.toml`:
```toml
rand-zkvm-cuda = { path = "../../../circuits/rand-zkvm-cuda", optional = true }
[features]
default = []
reference-backend = ["dep:rand-zkvm-cuda"]
mock-cuda = ["cuda", "rand-zkvm-cuda/mock-driver"]
cuda = ["dep:rand-zkvm-cuda", "rand-zkvm-cuda/cuda"]
```
and in `shrugg-client/Cargo.toml`: `[features] cuda = ["shrugg-zkvm/cuda"]`, `mock-cuda = ["shrugg-zkvm/mock-cuda"]`.

- [ ] **Step 2: Failing test** (append to `crates/shrugg-zkvm/tests/executor.rs`)
```rust
#[test]
fn prove_takes_a_backend_and_cpu_is_unchanged() {
    let p = guests::private_payment(1000);
    let (proof, outputs, tier) = prove(FriProfile::Test, &p, &[400, 250, 300, 75], None, shrugg_zkvm::machine::Backend::Cpu).unwrap();
    let ex = ZkExecutor::new(FriProfile::Test);
    let out = ex.verify_call(&record(&p), &proof).unwrap();
    assert_eq!((out.outputs, out.tier), (outputs, tier));
}
```
- [ ] **Step 3: Implement** — `executor::prove` gains the `backend` parameter and calls `m.prove_with(backend, ...)`; update the existing `shared()` helper in the test to pass `Backend::Cpu`. In `shrugg-client/src/main.rs`, add to `Cmd::Call`:
```rust
/// Prove on an attached NVIDIA GPU (requires a build with `--features cuda`).
#[arg(long)]
cuda: bool,
```
and in the handler, before proving:
```rust
let backend = if cuda {
    #[cfg(feature = "cuda")] { shrugg_zkvm::machine::Backend::Cuda }
    #[cfg(not(feature = "cuda"))] { anyhow::bail!("built without CUDA support; rebuild shrugg with --features cuda") }
} else { shrugg_zkvm::machine::Backend::Cpu };
let (proof, outputs, tier) = executor::prove(profile, &prog, &inputs, tier, backend).map_err(|e| anyhow::anyhow!(e))?;
```
`ProveError::Backend` already formats the `CudaError` text, so a missing driver or PTX prints e.g. `no PTX for the GPU kernels at .../ptx/kernels.sm_80.ptx (see rand-zkvm-cuda/ptx/PTX_BUILD.md)` and exits non-zero. Update `deploy/sync-zkvm.sh` to also copy nothing new (the CUDA crate is referenced by path, not vendored) and to print a reminder that `circuits/rand-zkvm-cuda` must be checked out beside `fullnode` when building with `--features cuda`.

- [ ] **Step 4: Docs** — add to `fullnode/docs/confidential.md` a `## GPU proving (--cuda)` section: how to build (`cargo build -p shrugg-client --features cuda` on a machine with CUDA 13 + driver + the committed PTX), the flag, the exact error texts without the feature / without a GPU / without PTX, and the statement that as of this date the kernels have not been executed on hardware.
- [ ] **Step 5: Verify** — `cargo test -p shrugg-zkvm` (all pass), `cargo build -p shrugg-client` (default), `cargo test -p shrugg-zkvm --features mock-cuda --test executor` (the executor's real-proof test still passes because verification is CPU-only), `cargo build -p shrugg-client --features mock-cuda` then `target/debug/shrugg ... call --cuda` against a local node proves through the mock driver.
- [ ] **Step 6: Commit both repos** — circuits: `git commit -m "research: cuda/reference feature wiring"`; fullnode: `git commit -m "client: --cuda flag (feature-gated, no fallback); executor takes a prove backend"` and push fullnode to main. Do **not** rebuild the droplets or restart node A (chain 4 fork pending, owned by the fleet session).

---

## Self-review

- **Spec coverage.** Crates/build → Tasks 1, 7, 8. NTT backend (bit-reversed evaluations view, chunked columns, two-level twiddles, shared-memory tiles) → Tasks 3, 4, 9. Merkle backend (salts via `StdRng`, tallest-first stable order, injection, cap, pruned multi-proofs, verification delegated to Plonky3) → Tasks 5, 6, 9. `Backend`, `prove_with`, proof conversion, key config sharing → Task 10. `--cuda`, feature gating, exact errors, no fallback → Task 11. Error handling (`CudaError`, `ProveError::Backend`, panic-at-trait-boundary converted at `prove_with`) → Tasks 8–10; note `prove_on` does not yet catch unwinds from inside `Mmcs::commit`: add `std::panic::catch_unwind` around `prove_batch` in Task 10 Step 3 if a `CudaError` panic must become `ProveError::Backend` rather than abort the CLI. Reference twins + no-GPU testing → every task's tests; hardware tests (`cuda-hw`) are deferred to the first GPU run, as the spec states.
- **Deviation from spec, deliberate:** the spec described `ProverData` as Plonky3's `MerkleTree`; this plan keeps the tree in `rand_zkvm_cuda::merkle::Tree` and re-implements `open_batch`/pruned multi-openings because the Plonky3 tree fields are crate-private and rebuilding one via serde would copy every leaf matrix. Verification still delegates to Plonky3, and Task 6 asserts byte-identical multi-proofs.
- **Placeholder scan:** `key_rngs` body and the `prove_on` bounds are stated as "copy from the existing function" on purpose — the executor must read `key_config` and `prove_batch`'s signature in the checked-out tree, which the other session is editing; the plan pins what must be preserved (deterministic seeds from `program_digest`, identical FRI parameters).
- **Type consistency:** `NttEngine` method names/signatures identical in Tasks 3, 4, 9; `HashEngine` identical in 5, 6, 9; `Arg` variants identical in 8, 9; kernel parameter orders identical in 7 (wrappers), 8 (mock dispatch), 9 (launch calls).
