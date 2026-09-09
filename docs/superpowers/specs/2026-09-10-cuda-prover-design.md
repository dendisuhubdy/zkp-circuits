# CUDA prover backend for the Rand zkVM — design

Date: 2026-09-10. Status: approved in discussion, awaiting spec review.

## Goal

Move the two dominant costs of `prove_batch` — the low-degree extension NTTs and the
Poseidon2 Merkle commitments — onto an NVIDIA GPU, behind a `--cuda` flag on the
`shrugg` client, without changing what a verifier checks. A proof produced on the GPU
must be byte-identical in structure to a CPU proof and must verify under the unchanged
CPU `Machine::verify`, so full nodes never link CUDA.

Not in scope: quotient evaluation, FRI folding and query openings on the device; a
verifier on the GPU; any change to the AIRs, buses, tiers, or FRI parameters.

## Constraints that shaped the design

1. **The zkVM is pinned to stable Rust 1.98.1**; cuda-oxide compiles kernels through a
   custom rustc codegen backend pinned to `nightly-2026-08-28`, needs CUDA Toolkit 13
   and LLVM 21+ to build, and a CUDA 13 (R580+) driver to run.
2. **`cuda-core` 0.3.1** (the host runtime cuda-oxide shares with cutile-rs, published
   from NVlabs/cutile-rs) is a normal crate with `rust-version = "1.89"` and can load
   PTX at runtime (`load_module_from_ptx_src`, `load_function`, `DeviceBuffer`,
   streams). Its build script, however, requires a CUDA 13 toolkit at *build* time
   (verified 2026-09-10: the build fails on macOS without `CUDA_HOME`). It therefore
   cannot be an unconditional dependency of either repo.
3. **No GPU is available to the author** (Apple M4 Max laptop; 2-vCPU droplets). The
   device code is written unverified; correctness is carried by CPU reference twins.
4. **Verifier compatibility.** The verifier uses `StarkConfig<HidingFriPcs<Val,
   Radix2DitParallel, MerkleTreeHidingMmcs<…, 2, 4, 4>, …>>`. Commitments are a
   `MerkleCap` of 2^cap_height = 4 digests of 4 Goldilocks elements; openings are
   `(Vec<Vec<Val>>, Vec<[Val; 4]>)` (per-matrix rows including salts, sibling digests).
   The GPU backend reuses these exact types, and its digests must equal the CPU tree's
   bit for bit.

## Crates and build

```
circuits/
  research/            existing zkVM (stable). New optional feature `cuda`.
  rand-zkvm-cuda/      NEW, stable. Host backend: GpuDft, GpuHidingMmcs, probe, PTX loader.
  gpu-kernels/         NEW, cuda-oxide crate (nightly). #[kernel] functions only.
fullnode/
  crates/shrugg-zkvm   gains feature `cuda` = ["rand-zkvm-cuda"] (vendored copy of research)
  crates/shrugg-client gains feature `cuda` and the `--cuda` flag on `call`
```

### `gpu-kernels` (cuda-oxide, nightly)

- One `#[cuda_module] mod kernels` with the kernels listed below. No host code.
- `rust-toolchain.toml` pins `nightly-2026-08-28` with `rust-src`, `rustc-dev`,
  `llvm-tools`. Built with `cargo oxide build --release --target sm_80`.
- The generated PTX is copied to `rand-zkvm-cuda/ptx/kernels.sm_80.ptx` and committed,
  with a `PTX_BUILD.md` recording the cuda-oxide commit and toolkit version used. A
  `Justfile` recipe `kernels` performs the build + copy on a machine with the toolkit.
- Until someone runs that recipe, the PTX file is absent and `GpuProver::probe()`
  fails with `CudaError::MissingPtx`. The crate still builds and its CPU tests run.

### `rand-zkvm-cuda` (stable)

Dependencies: `cuda-core = "=0.3.1"`, `p3-field`, `p3-dft`, `p3-matrix`, `p3-commit`,
`p3-merkle-tree`, `p3-goldilocks`, `p3-poseidon2`, `p3-symmetric`, `p3-util` (all
`=0.7.0`), `rand`, `thiserror`.

Public surface:

```rust
pub struct GpuProver { ctx: Arc<CudaContext>, stream: CudaStream, module: Arc<CudaModule>,
                       twiddles: TwiddleCache, poseidon: PoseidonConstants }
impl GpuProver {
    /// Opens device 0, loads the PTX, uploads Poseidon2 constants. Every failure is a
    /// `CudaError` naming the stage (driver, context, ptx, alloc).
    pub fn probe() -> Result<Arc<Self>, CudaError>;
}
#[derive(Clone)] pub struct GpuDft(Arc<GpuProver>);        // impl TwoAdicSubgroupDft<Goldilocks>
#[derive(Clone)] pub struct GpuHidingMmcs { gpu: Arc<GpuProver>, hash, compress,
                                            cap_height: usize, rng: Arc<Mutex<StdRng>> }
                                                            // impl Mmcs<Goldilocks>
pub mod reference;   // pure-Rust twins with identical layouts (always compiled)
```

`TwoAdicSubgroupDft` requires `Default`; `GpuDft::default()` calls `probe()` and
panics with the `CudaError` if it fails. `Machine::prove_with(Backend::Cuda)` calls
`probe()` first so the panic path is never reached in practice.

### `research` feature `cuda`

```rust
#[cfg(feature = "cuda")]
pub type CudaValMmcs = rand_zkvm_cuda::GpuHidingMmcs;
#[cfg(feature = "cuda")]
pub type CudaPcs = HidingFriPcs<Val, rand_zkvm_cuda::GpuDft, CudaValMmcs, ExtensionMmcs<Val, Challenge, CudaValMmcs>, StdRng>;
#[cfg(feature = "cuda")]
pub type CudaConfig = StarkConfig<CudaPcs, Challenge, Challenger>;

pub enum Backend { Cpu, #[cfg(feature = "cuda")] Cuda,
                   #[cfg(feature = "reference-backend")] Reference }  // test-only twins

impl Machine {
    pub fn prove(&self, …)                       // unchanged, CPU
    pub fn prove_with(&self, backend: Backend, program, inputs, tier)
        -> Result<(Proof, Execution), ProveError>;   // Cuda: builds a CudaConfig from the same
                                                     // profile/RNG seeding rules as make_config
}
```

`Proof` is unchanged: `p3_batch_stark::Proof<Config>` is generic over the Pcs only
through its associated `Commitment`/`Proof` types, which are identical between the CPU
and CUDA configs, so `Proof::to_bytes`/`from_bytes` and `verify` are untouched. A unit
test asserts `size_of`/serde equality of the two proof types.

`build_config`'s seeding rules (`mmcs_rng`, `pcs_rng` from OS entropy for `prove_batch`;
deterministic from `program_digest` for `key_config`) apply unchanged to the CUDA
config. The verifier key is always computed on the CPU (`verifier_key` is verifier-side
work and must not depend on CUDA).

### Fullnode

- `crates/shrugg-zkvm/Cargo.toml`: `[features] cuda = ["dep:rand-zkvm-cuda"]`, path
  dependency `../../../circuits/rand-zkvm-cuda` (same pattern as the vendored crate:
  `deploy/sync-zkvm.sh` copies the feature-gated source; the CUDA crate itself is not
  vendored).
- `executor::prove` gains a `backend: Backend` argument. `ZkExecutor` (node side,
  verify only) is untouched.
- `shrugg call … --cuda`: with the feature, `Backend::Cuda`; without it, the flag is
  still parsed and returns the error `built without CUDA support; rebuild shrugg with
  --features cuda`. With the feature and no usable device, the `CudaError` from
  `probe()` is printed and the command exits non-zero. There is no silent CPU fallback.
- `shrugg-node` never enables the feature.

## NTT backend

### What the PCS calls

`HidingFriPcs::commit` calls `dft.coset_lde_batch(evals, log_blowup + 1, shift)` per
matrix (the `+1` is the hiding profile's extra random column blowup) and then
`.bit_reverse_rows()`; `TwoAdicFriPcs` (inner) calls `coset_lde_batch(evals,
log_blowup, shift)` for quotient chunks and `coset_idft_batch(lde, GENERATOR)` once.
All inputs are `RowMajorMatrix<Goldilocks>`: rows are evaluation points, columns are
polynomials.

### `GpuDft`

- `type Evaluations = BitReversedMatrixView<RowMajorMatrix<Goldilocks>>`, the same as
  `Radix2DitParallel`, so the PCS's `bit_reverse_rows()` is a free view flip.
- `dft_batch(mat)`: upload, forward NTT (DIT, output in bit-reversed order), download.
- `coset_lde_batch(mat, added_bits, shift)`: upload; inverse NTT (natural-order
  coefficients, scaled by n⁻¹); zero-extend each column to `n << added_bits`; multiply
  coefficient *i* by `shift^i`; forward NTT into bit-reversed order; download.
- `coset_idft_batch(mat, shift)`: upload; inverse NTT; multiply coefficient *i* by
  `shift^-i`; download in natural order.
- Sizes: heights are powers of two from 2^10 (cpu table, tier 10) to 2^22 (memory table
  at tier 20) before blowup; after the hiding blowup (log_blowup 3 + 1) the largest NTT
  is 2^26 points. Widths up to ~60 columns (cpu table is 52 + 4 salt). Peak device
  memory for one matrix at 2^26 × 56 × 8 B ≈ 30 GB is too large for most cards, so
  `coset_lde_batch` processes columns in chunks sized from `ctx.free_memory()`; each
  chunk is one NTT batch. Tier 20 is therefore supported but memory-bound; tiers ≤ 18
  (≤ 2^24 points, ≤ 7.5 GB) fit a 16 GB card in one pass.

### Kernels (all Goldilocks, `p = 2^64 − 2^32 + 1`, elements as `u64`)

| kernel | grid | work |
|---|---|---|
| `gl_mul_pow` | 1 thread / element | `x[i] *= base^i` (coset shift, inverse shift, n⁻¹ fold) |
| `bit_reverse_rows` | 1 thread / element | permute rows by bit-reversed index (used for iNTT input) |
| `ntt_stage_global` | 1 thread / butterfly | one radix-2 DIT stage with stride ≥ 2^10, twiddle from table |
| `ntt_stages_shared` | 1 block / 2^10-point tile / column | the last 10 stages in shared memory (8 KB per column tile), synchronised with `barrier::sync` |
| `column_zero_extend` | 1 thread / element | copy an `n×w` tile into an `(n<<k)×w` buffer, zero the rest |

Field arithmetic is a device-side module `gl.rs` (shared by kernels): add/sub with
conditional subtraction, `mul` via 128-bit product `hi:lo` reduced as
`lo − hi_hi·1 + hi_lo·2^32` with the standard two-step correction, `pow` by squaring,
`inv` by Fermat (only used on the host). Twiddle tables `ω_n^i` for every `n` in the
size range are computed on the host once per `GpuProver` and uploaded (`2^26` entries
= 512 MB is too much; tables are stored per stage size ≤ 2^13 and larger stages
compute `ω^i` as `table[i mod 2^13] · pow2table[i >> 13]`).

Layout on device: column-major per chunk (`col * n + row`) so that a butterfly's two
operands are contiguous within a column and threads across columns coalesce. The
host transposes on upload/download with a `transpose` kernel rather than on the CPU.

## Merkle backend

### CPU tree semantics to reproduce

`MerkleTreeHidingMmcs::commit(inputs)`:
1. For each matrix in the given order, `salts = RowMajorMatrix::rand(&mut rng,
   height, 4)` (Goldilocks `Standard` distribution, `StdRng`), appended as 4 trailing
   columns.
2. `MerkleTree::new` sorts matrices by height, largest first (stable), and validates
   that every height is `ceil(max_height / 2^k)` for some `k`.
3. First digest layer: for each row *r* of the tallest height, the padding-free
   Poseidon2 sponge (width 8, rate 4, out 4) absorbs the concatenation of row *r* of
   every matrix at that height (each including its salts), 4 elements per permutation,
   no padding; the digest is state[0..4].
4. Each next layer: `compress_and_inject` — compress adjacent pairs with the truncated
   permutation (state = left ‖ right, one permutation, keep state[0..4]); if matrices
   exist whose height's next power of two equals the new layer length, hash their
   rows with the sponge and compress the pair-digest with that row digest.
   `select_arity_step` is always 2 here (N = 2); the schedule is recorded.
5. `MerkleCap`: the layer with `2^cap_height` = 4 digests.

`open_batch(index)`: for each matrix, row `index >> (log_max_height − log_height)`
including salts; siblings from each layer above the cap.

### `GpuHidingMmcs`

- `type Commitment = MerkleCap<Goldilocks, [Goldilocks; 4]>`,
  `type Proof = (Vec<Vec<Goldilocks>>, Vec<[Goldilocks; 4]>)`,
  `type ProverData<M> = GpuTree<M>` (our struct: salted leaf matrices kept on the
  host for `open_batch`/`get_matrices`, and the downloaded `digest_layers`).
- `commit`: salts on the host with the same `StdRng` calls (step 1), upload the salted
  matrices, run `poseidon2_rows` for the first layer, then alternate
  `poseidon2_compress` and (at injection layers) `poseidon2_rows` + `poseidon2_compress`
  exactly per the schedule computed by a host-side copy of Plonky3's scheduling
  (`select_arity_step`, `padded_len`). Download all layers (they total < 2× the leaf
  count × 32 B).
- `open_batch`, `get_matrices`, `get_max_height`, `verify_batch`: host-side, copied
  from Plonky3's `MerkleTree`/`MerkleTreeMmcs` logic over our layers. `verify_batch` is
  implemented for trait completeness and is tested equal to the CPU one, but the node
  never uses it.
- `ExtensionMmcs<Val, Challenge, GpuHidingMmcs>` wraps it unchanged for FRI commits.

### Kernels

| kernel | grid | work |
|---|---|---|
| `poseidon2_rows` | 1 thread / row | sponge over `w` elements of row *r* from up to *k* matrices (pointer table + widths in a small constant buffer) |
| `poseidon2_compress` | 1 thread / pair | one permutation on `left ‖ right`, write 4 elements |
| `poseidon2_inject` | 1 thread / pair | fused: compress pair, then compress with the injected row digest |

`poseidon2.rs` (device): width-8 Poseidon2 over Goldilocks with 8 external rounds
(4 initial, 4 terminal), 22 internal rounds, S-box x^7, external 4×4 MDS blocks with
the Plonky3 circulant layer, internal diagonal `MATRIX_DIAG_8_GOLDILOCKS`. Round
constants come from the host: `Poseidon2Goldilocks::<8>::new_from_rng_128(StdRng::
seed_from_u64(PERM_SEED))` is not introspectable, so the host regenerates the same
sequence with `ExternalLayerConstants::new_from_rng(8, rng)` followed by the internal
constants draw in the same order `new_from_rng_128` uses (verified by a test that the
regenerated permutation equals Plonky3's on random inputs), and uploads 8×8 + 22
elements to constant memory.

## Reference twins and testing (no GPU required)

`rand_zkvm_cuda::reference` contains, for every kernel, a pure-Rust function with the
same signature over slices and the same element order:

- `gl` arithmetic → tested against `p3_goldilocks::Goldilocks` on random and edge
  values (0, 1, p−1, 2^32, 2^32−1, 2^64−1 after reduction).
- `ntt_forward`/`ntt_inverse` with the same twiddle tables and stage order → equal to
  `Radix2DitParallel::dft_batch` / `coset_lde_batch` / `coset_idft_batch` for every
  height 2^10..2^22 (smaller sizes exhaustively, larger sampled) and widths 1, 7, 56.
- `poseidon2_permute` → equal to `Poseidon2Goldilocks<8>` on 10⁴ random states.
- `merkle_commit`/`open` → identical cap and identical `open_batch` output to
  `MerkleTreeHidingMmcs` for mixed-height matrix sets shaped like every tier
  (5 tables + 1 random column), with both sides seeded from the same `StdRng`.
- `ReferenceDft`/`ReferenceHidingMmcs` implement the same Plonky3 traits over the
  twins, so `Machine::prove_with(Backend::Reference)` (feature `reference-backend`,
  test-only) proves every guest and `Machine::verify` accepts the result. This is the
  end-to-end contract the GPU path inherits.

The GPU path is the same host code with slice operations replaced by kernel launches
over the same buffers. Tests that need a device are behind `#[cfg(feature =
"cuda-hw")]` and run `cargo test --features cuda-hw` on a machine with a driver; they
compare `GpuDft`/`GpuHidingMmcs` against the reference twins on the same inputs, then
prove and verify every guest. The spec and README state plainly that, until that run
happens, the kernels are untested.

## Error handling

```rust
pub enum CudaError { Driver(String), Context(String), MissingPtx(PathBuf),
                     PtxLoad(String), Alloc { bytes: usize, free: usize },
                     Launch { kernel: &'static str, msg: String }, Copy(String) }
```

`ProveError` gains `Backend(CudaError)`. `Mmcs::commit` and `dft_batch` cannot return
errors, so inside those the backend panics with the `CudaError` Display string; the
client catches the unwind at the `prove_with` boundary and converts it to
`ProveError::Backend`. Out-of-memory is reported with the requested and free bytes and
a hint to use a lower tier; there is no retry on the CPU.

## Performance expectations (to be measured, not promised)

Current laptop prove: 21 s for `private_payment` at tier 10 (production profile).
Prove time is dominated by LDE + commit for the 5 main matrices, the quotient, and the
FRI layers. A mid-range card should bring the NTT and hashing to well under a second
for tiers ≤ 16; host↔device copies (30–60 MB per matrix at tier 10, ×4 for LDE) and the
remaining CPU work (quotient evaluation, FRI folds, challenger) become the floor. Those
are the follow-on candidates once measurements exist.

## Milestones

1. `rand-zkvm-cuda` crate with `reference` twins and all CPU-side equality tests;
   `Machine::prove_with(Backend::Reference)` proves and verifies every guest.
2. `gpu-kernels` crate and the host launch code in `GpuDft`/`GpuHidingMmcs`; compiles
   on stable without a toolkit (feature-gated); `probe()` and `CudaError` complete.
3. `research` feature `cuda`, fullnode `cuda` feature and `--cuda` flag, sync script
   updated, docs.
4. First hardware run: build PTX, commit it with `PTX_BUILD.md`, run `cuda-hw` tests,
   record measured numbers here.
