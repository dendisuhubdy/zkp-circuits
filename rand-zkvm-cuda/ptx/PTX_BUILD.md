# PTX_BUILD.md
Status: **no PTX has been built yet.** `gpu-kernels` has never been compiled: the author's
machines have no NVIDIA GPU and no CUDA 13 toolkit. `GpuProver::probe()` returns
`CudaError::MissingPtx` until `kernels.sm_80.ptx` exists here.

To build: on a Linux box with an R580+ driver, CUDA 13, LLVM 21 and the pinned nightly,
`cd gpu-kernels && just kernels sm_80`, then fill in:
- cuda-oxide commit: `26754ae52c26c097dc1c465a1e42c4c5d05a3d40` (cloned 2026-09-10, dated
  2026-09-06; pinned as `rev` in `gpu-kernels/Cargo.toml`)
- CUDA toolkit: (unfilled)
- built on: (unfilled)
and run `cargo test -p rand-zkvm-cuda --features cuda-hw`.

## Unverified details

Nothing below has been run. In particular:

- The `cargo oxide build --arch sm_80` flag spelling in `gpu-kernels/Justfile` is a guess at
  `cargo-oxide`'s CLI and may need adjusting (a different flag name, or `--target`-style
  spelling).
- The output filename the `Justfile` copies, `rand-zkvm-kernels.ptx`, is likewise a guess: it
  assumes the emitted PTX is named after the `[[bin]]` target and lands in the crate root.
  Check what `cargo oxide build` actually writes and fix the `cp` line.

## First hardware run

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
- The shared kernel bodies in `src/device/kernels.rs` contain `unwrap` and `copy_from_slice`
  calls, i.e. panic paths. cuda-oxide may reject them outright (no panic machinery on device),
  in which case they have to be rewritten as unchecked indexing/manual copies.
- `dif_tiles` launches with `tile / 2` threads per block; for `n = 2` that is a single thread
  per block, which is legal but exercises the barrier path degenerately.
