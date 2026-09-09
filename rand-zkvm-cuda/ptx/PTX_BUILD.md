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
