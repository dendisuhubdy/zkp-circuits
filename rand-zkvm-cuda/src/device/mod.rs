//! Code shared verbatim with the cuda-oxide kernel crate (`gpu-kernels` includes these
//! files by `#[path]`). No dependencies, no allocation, no std.
pub mod gl;
pub mod kernels;
pub mod poseidon2;
