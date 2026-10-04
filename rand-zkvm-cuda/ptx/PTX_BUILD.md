# PTX_BUILD.md
Status: **built and run on hardware once (2026-09-28, below); no PTX is committed.**
`GpuProver::probe()` returns `CudaError::MissingPtx` until `kernels.sm_80.ptx` exists here (or
`RAND_ZKVM_PTX` names one), so build it on the proving machine.

To build: on a Linux box with an R580+ driver, CUDA 13, LLVM 21 and the pinned nightly,
`cd gpu-kernels && just kernels sm_80`, then fill in:
- cuda-oxide commit: `26754ae52c26c097dc1c465a1e42c4c5d05a3d40` (cloned 2026-09-10, dated
  2026-09-06; pinned as `rev` in `gpu-kernels/Cargo.toml`)
- CUDA toolkit: 13.1 (V13.1.115), driver 580.173.02, LLVM 21.1.8, rustc nightly-2026-08-28
- built on: DigitalOcean `gpu-h100x1-80gb` (NVIDIA H100 80GB HBM3, sm_90), Ubuntu 22.04, image
  "NVIDIA AI/ML Ready", 2026-09-28
and run `cargo test -p rand-zkvm-cuda --features cuda-hw` (`tests/gpu_hw.rs`).

## Compile-only check (2026-09-28, no GPU)

`cargo oxide build --arch sm_80` at the pinned cuda-oxide rev, run on a GPU-less Ubuntu 24.04
box without the CUDA toolkit (cargo-oxide uses the Rust toolchain's `llc`), builds the
kernels. The flag spelling is right, and the output is `rand_zkvm_kernels.ptx` in
`gpu-kernels/` (the `Justfile`'s `cp` line now uses that name). The PTX was not committed:
this file's toolkit and "built on" lines are for the real build (below).

## First hardware run (2026-09-28, H100, circuits `feat/r4a-gpu-aliasing-cs7`)

Run for R4-a (randprotocol/fullnode#49), on this branch and on its base `b9ffc39` (the base
built only with the `poseidon2_compress`/`_inject` digest-array change of this branch applied
as a scratch patch, which is the only way it lowers to PTX).

- `cargo oxide build --arch sm_80` and `--arch sm_90` both build; each PTX has the eleven
  entries. Step 1 below holds: `to_col_major` has 6 params (ptr, len, ptr, len, u32, u32),
  `poseidon2_rows` 8 (ptr, len, u32, u32, ptr, len, ptr, len), `dif_tiles` 9 — what
  `real.rs::Device::launch` packs. Step 4 holds: `real.rs` compiles against `cuda-core 0.3.1`.
- `cargo test --release --features cuda-hw` with `RAND_ZKVM_PTX` at the sm_90 and at the sm_80
  PTX (JIT-compiled by the driver): every test passes on both trees, including
  `tests/gpu_hw.rs` — the ABI round trip, every DFT entry point equal to the CPU twin and to
  Plonky3's `Radix2DitParallel` for log n = 1…16 and widths 1/6/56, the large-n `dif_tiles`
  cross-check (step 3: log n = 20 and 22, `dft_batch` and a coset LDE, against Plonky3), and
  Poseidon2 Merkle commitments and openings equal to the CPU twin's up to 2^18 rows. The
  `mock-driver` and default-feature suites pass on both trees too.
- `compute-sanitizer` 13.1 over `gpu_hw`'s ABI, DFT and Merkle tests (the large-n test left
  out for time), sm_90 PTX, both trees: memcheck 0 errors, racecheck 0 hazards (the
  `dif_tiles` shared tile included), synccheck 0 errors.
- Host side, Miri (nightly-2026-08-28, Stacked and Tree Borrows): `tests/cells_launch.rs` runs
  the kernel bodies as a parallel launch on host threads, each simulated GPU thread with its
  own `Cells::from_raw` over the shared buffer — clean. The pre-fix `all()` pattern
  (`from_raw_parts_mut` per thread) run the same way is reported as UB, a data race between
  the threads' `&mut [u64]` retags, under both models. The Plonky3-comparing suites cannot run
  under Miri (inline assembly).
- sha256 of the PTX this branch built: sm_80 `4142929d…be8f5`, sm_90 `4a16612d…7c5a7`.

## First hardware run: the checklist

1. **Verify the kernel parameter ABI before anything else.** Dump the generated PTX and read
   the `.param` list of `to_col_major` and `poseidon2_rows`:

   ```
   grep -A12 '\.visible \.entry to_col_major' ptx/kernels.sm_80.ptx
   grep -A12 '\.visible \.entry poseidon2_rows' ptx/kernels.sm_80.ptx
   ```

   Every `&[u64]` **and** every `DisjointSlice<u64>` parameter must lower to exactly two
   params — a `.u64` pointer followed by a `.u64` (`usize`) length — and the scalar `u32`s to
   one `.u32` each, in source order. That is precisely what `real.rs::Device::launch` packs
   (`Arg::Buf` pushes a pointer then a length; `Arg::U32`/`Arg::U64` push one word). So
   `to_col_major(src: &[u64], dst: DisjointSlice<u64>, rows: u32, cols: u32)` must show
   **6** params in this order: ptr, len, ptr, len, u32, u32. And
   `poseidon2_rows(rows: &[u64], width: u32, n: u32, k: &[u64], out: DisjointSlice<u64>)` must
   show **8**: ptr, len, u32, u32, ptr, len, ptr, len. If a `DisjointSlice` lowers to a fat
   struct, a single pointer, or adds a hidden parameter, **fix `real.rs`'s packing before
   trusting any kernel output** — a mismatched ABI silently reads garbage rather than failing.
2. Run the hardware test suite: `cargo test -p rand-zkvm-cuda --features cuda-hw`.
3. Cross-check `dif_tiles` against a `dif_stage`-only run for a large `n` (e.g. `n = 2^20`).
   `dif_tiles` is the only kernel that uses shared memory and a block-wide barrier; how
   cuda-oxide lowers that barrier is unverified, and a miscompiled barrier shows up only as a
   wrong transform at sizes above the tile.
4. Confirm the `cuda-core` symbol names in `real.rs::free_bytes` — `cuMemGetInfo_v2` and
   `cudaError_enum_CUDA_SUCCESS` — actually exist in the bindgen'd `cuda_core::sys` at the
   pinned version. They are spelled from memory and have never been compiled.
5. Start at tier 10 and walk the tiers up. The Merkle path uploads whole matrices at once, and
   `max_columns` is computed from a *probe-time* free-memory snapshot, so a large tier can ask
   for far more device memory than the snapshot implied. An oversized upload now reports
   `CudaError::Alloc` ("use a lower tier") rather than a bare copy failure.

## Notes / known rough edges

- Poseidon2 round constants are passed as an ordinary global buffer (`GpuProver::consts`), not
  in constant memory. This is a performance question only, not a correctness one.
- A relocated binary **must** set `RAND_ZKVM_PTX`: the default path is
  `<CARGO_MANIFEST_DIR>/ptx/kernels.sm_80.ptx`, i.e. the build machine's crate directory, and
  the default filename hardcodes `sm_80`.
- The shared kernel bodies in `src/device/kernels.rs` keep bounds-checked indexing (panic
  paths, lowered to traps). `try_into().unwrap()` on a slice is the one form cuda-oxide cannot
  lower (it pulls in `dyn Debug`); the digests are built as explicit arrays instead.
- `dif_tiles` launches with `tile / 2` threads per block; for `n = 2` that is a single thread
  per block, which is legal but exercises the barrier path degenerately.
